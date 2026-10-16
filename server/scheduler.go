package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Scheduler drives P3 triggers: on each tick it fires due interval triggers and
// scans for new findings / newly-met goals (any task) to fire event triggers.
// Each fire enqueues a NEW conversation on the agent's per-agent trigger queue
// (StartTriggeredRun): fires for the same agent run one at a time in FIFO order,
// distinct agents still run concurrently. State is persisted (per-trigger last_fire
// + finding watermark + fired-goal set) so a restart resumes without double-firing.
// Triggers only attach to CUSTOM agents.
type Scheduler struct {
	s    *Server
	pg   *db.DB
	tick time.Duration
}

const (
	schedKeyLastFinding    = "last_finding_id"    // watermark: max finding node id fired for
	schedKeyFiredGoals     = "fired_goals"        // JSON array of goal node ids already fired
	schedKeyLastTimeout    = "last_timeout_id"    // watermark: max task id fired for task timeout
	schedKeyLastToolCall   = "last_toolcall_id"   // watermark: max activity id fired for tool call
	schedKeyLastTaskCreate = "last_taskcreate_id" // watermark: max task id fired for task create
)

func newScheduler(s *Server) *Scheduler {
	return &Scheduler{s: s, pg: s.m.pg, tick: 5 * time.Second}
}

// Run loops until ctx is done, ticking the scheduler. Started once from server New.
func (sc *Scheduler) Run(ctx context.Context) {
	if sc.pg == nil {
		return
	}
	sc.init()
	t := time.NewTicker(sc.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sc.s.reconcileConcurrency() // 并发上限:有空位就把排队任务补位启动
			sc.refreshOutcomes(ctx)
			sc.step()
		}
	}
}

// init seeds the watermarks on first run so pre-existing findings/goals don't all
// fire at once — only events created AFTER the scheduler first starts count.
func (sc *Scheduler) init() {
	if sc.mustState(schedKeyLastFinding) == "" {
		var maxID int64
		if evs, err := sc.pg.NewFindingsSince(0); err == nil {
			for _, e := range evs {
				if e.NodeID > maxID {
					maxID = e.NodeID
				}
			}
		}
		_ = sc.pg.SetSchedState(schedKeyLastFinding, strconv.FormatInt(maxID, 10))
	}
	if sc.mustState(schedKeyFiredGoals) == "" {
		set := map[int64]bool{}
		if evs, err := sc.pg.MetGoals(); err == nil {
			for _, e := range evs {
				set[e.NodeID] = true
			}
		}
		sc.saveFiredGoalSet(set)
	}
	if sc.mustState(schedKeyLastTimeout) == "" {
		var maxID int64
		if evs, err := sc.pg.TimedOutTasksSince(0); err == nil {
			for _, e := range evs {
				if e.NodeID > maxID {
					maxID = e.NodeID
				}
			}
		}
		_ = sc.pg.SetSchedState(schedKeyLastTimeout, strconv.FormatInt(maxID, 10))
	}
	if sc.mustState(schedKeyLastToolCall) == "" {
		var maxID int64
		if evs, err := sc.pg.NewToolCallsSince(0); err == nil {
			for _, e := range evs {
				if e.NodeID > maxID {
					maxID = e.NodeID
				}
			}
		}
		_ = sc.pg.SetSchedState(schedKeyLastToolCall, strconv.FormatInt(maxID, 10))
	}
	if sc.mustState(schedKeyLastTaskCreate) == "" {
		var maxID int64
		if evs, err := sc.pg.NewTasksSince(0); err == nil {
			for _, e := range evs {
				if e.NodeID > maxID {
					maxID = e.NodeID
				}
			}
		}
		_ = sc.pg.SetSchedState(schedKeyLastTaskCreate, strconv.FormatInt(maxID, 10))
	}
}

// outcomeGrace is how long a terminal task is left alone before its outcome is computed.
// A task is marked done BEFORE its running workers are cancelled, so they keep writing
// for a short while after; computing at the instant of completion would systematically
// undercount.
const outcomeGrace = 30 * time.Second

// outcomeBatch caps how many tasks one tick recomputes, so a backlog (e.g. the first
// sweep after upgrading an existing database) is spread over several ticks instead of
// stalling startup.
const outcomeBatch = 50

// refreshOutcomes computes the post-run summary for terminal tasks that need one.
//
// Driven from the scheduler tick rather than from the status transition, for two reasons:
// the grace period above, and self-healing — a task that finished while the server was
// down is picked up on the next pass. There is deliberately no manual recompute endpoint;
// this is the only writer.
func (sc *Scheduler) refreshOutcomes(ctx context.Context) {
	ids, err := sc.pg.TasksNeedingOutcome(outcomeGrace, outcomeBatch)
	if err != nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		o, err := sc.pg.ComputeTaskOutcome(ctx, id)
		if err != nil {
			log.Printf("[outcome] task %d 汇总失败: %v", id, err)
			continue
		}
		if o == nil {
			continue // 任务已不存在
		}
		if err := sc.pg.UpsertTaskOutcome(ctx, o); err != nil {
			log.Printf("[outcome] task %d 落库失败: %v", id, err)
		}
		// 共享大脑的写入侧：把本任务 observed 级结论提炼进全局经验库（幂等，
		// 同名跳过）。放在 outcome 落定之后 —— 只有确认任务真的结束才提炼。
		sc.deriveLessons(id, sc.s.m.dir)
	}
}

func (sc *Scheduler) step() {
	triggers, err := sc.pg.ListEnabledTriggers()
	if err != nil {
		return
	}
	if len(triggers) == 0 {
		return
	}
	sc.fireIntervals(triggers)
	sc.fireFindings(triggers)
	sc.fireGoals(triggers)
	sc.fireTaskTimeouts(triggers)
	sc.fireToolCalls(triggers)
	sc.fireTaskCreates(triggers)
}

// fireIntervals fires triggers whose interval has elapsed since last_fire.
func (sc *Scheduler) fireIntervals(triggers []*db.AgentTrigger) {
	now := time.Now()
	for _, tr := range triggers {
		if tr.IntervalSec <= 0 {
			continue
		}
		due := tr.LastFire == nil || now.Sub(*tr.LastFire) >= time.Duration(tr.IntervalSec)*time.Second
		if !due {
			continue
		}
		_ = sc.pg.TouchTriggerFire(tr.ID)
		ctx := "\n\n【本次为定时触发】" + now.Format(" 2006-01-02 15:04:05 MST")
		sc.s.StartTriggeredRun(tr.AgentKey, fmt.Sprintf("定时触发 · %s", now.Format("15:04")), tr.IntervalMessage+ctx, 0, false, "", "")
	}
}

// fireFindings fires on_finding triggers for findings above the persisted
// watermark (monotonic node id → no double-fire across restarts).
func (sc *Scheduler) fireFindings(triggers []*db.AgentTrigger) {
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnFinding {
			want = append(want, tr)
		}
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastFinding), 10, 64)
	events, err := sc.pg.NewFindingsSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	// Advance the watermark whether or not any on_finding trigger is active: a
	// finding fires only for triggers live at the moment it appears. Otherwise a
	// trigger enabled later would replay the entire historical backlog at once.
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		if len(want) == 0 {
			continue
		}
		msgCtx := fmt.Sprintf("\n\n【本次由任务发现 finding 触发】\n发现: [%s/%s] %s",
			e.VulnClass, e.Severity, e.Summary)
		for _, tr := range want {
			sc.s.StartTriggeredRun(tr.AgentKey, fmt.Sprintf("finding 触发 · task#%d", e.TaskID), tr.FindingMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = sc.pg.SetSchedState(schedKeyLastFinding, strconv.FormatInt(maxID, 10))
}

// fireGoals fires on_goal_met triggers for met goals not yet in the fired set.
func (sc *Scheduler) fireGoals(triggers []*db.AgentTrigger) {
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnGoalMet {
			want = append(want, tr)
		}
	}
	events, err := sc.pg.MetGoals()
	if err != nil || len(events) == 0 {
		return
	}
	// Mark goals as consumed whether or not a trigger is active, so enabling an
	// on_goal_met trigger later doesn't replay every already-met goal.
	fired := sc.firedGoalSet()
	changed := false
	for _, e := range events {
		if fired[e.NodeID] {
			continue
		}
		fired[e.NodeID] = true
		changed = true
		if len(want) == 0 {
			continue
		}
		msgCtx := fmt.Sprintf("\n\n【本次由任务完成目标触发】\n达成目标: %s", e.Summary)
		for _, tr := range want {
			sc.s.StartTriggeredRun(tr.AgentKey, fmt.Sprintf("目标触发 · task#%d", e.TaskID), tr.GoalMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	if changed {
		sc.saveFiredGoalSet(fired)
	}
}

// fireTaskTimeouts fires on_task_timeout triggers for tasks that newly reached
// status='timeout' above the persisted watermark (task id → no double-fire).
func (sc *Scheduler) fireTaskTimeouts(triggers []*db.AgentTrigger) {
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnTaskTimeout {
			want = append(want, tr)
		}
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastTimeout), 10, 64)
	events, err := sc.pg.TimedOutTasksSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	// Advance the watermark even with no active trigger — see fireFindings.
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		if len(want) == 0 {
			continue
		}
		msgCtx := "\n\n【本次由任务超时触发】"
		for _, tr := range want {
			sc.s.StartTriggeredRun(tr.AgentKey, fmt.Sprintf("超时触发 · task#%d", e.TaskID), tr.TaskTimeoutMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = sc.pg.SetSchedState(schedKeyLastTimeout, strconv.FormatInt(maxID, 10))
}

// fireTaskCreates fires on_task_create triggers for tasks newly created above the
// persisted watermark (task id → no double-fire across restarts).
func (sc *Scheduler) fireTaskCreates(triggers []*db.AgentTrigger) {
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnTaskCreate {
			want = append(want, tr)
		}
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastTaskCreate), 10, 64)
	events, err := sc.pg.NewTasksSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	// Advance the watermark even with no active trigger — see fireFindings.
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		if len(want) == 0 {
			continue
		}
		msgCtx := "\n\n【本次由任务创建触发】"
		for _, tr := range want {
			sc.s.StartTriggeredRun(tr.AgentKey, fmt.Sprintf("任务创建触发 · task#%d", e.TaskID), tr.TaskCreateMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = sc.pg.SetSchedState(schedKeyLastTaskCreate, strconv.FormatInt(maxID, 10))
}

// fireToolCalls fires on_tool_call triggers for tool calls (tool_result rows) above
// the persisted watermark whose tool name is in the trigger's selected set. The fire
// message carries the task id/desc/goal + tool name + (truncated) input & output.
func (sc *Scheduler) fireToolCalls(triggers []*db.AgentTrigger) {
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnToolCall && len(tr.ToolNames) > 0 {
			want = append(want, tr)
		}
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastToolCall), 10, 64)
	events, err := sc.pg.NewToolCallsSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	// Advance the watermark even with no active trigger — see fireFindings.
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		if len(want) == 0 {
			continue
		}
		// A failed finding write has no committed finding to report. Keep other
		// tool-error triggers available for user-defined automation.
		if e.ToolIsErr && e.Tool == "report_finding" {
			continue
		}
		errTag := ""
		if e.ToolIsErr {
			errTag = "[error] "
		}
		msgCtx := fmt.Sprintf("\n\n【本次由工具调用触发】\n工具: %s\n入参: %s\n返回: %s%s",
			e.Tool, trunc(e.ToolInput, 1500), errTag, trunc(e.ToolOutput, 1500))
		// report_finding 的返回里带着刚登记的那条漏洞的 finding_id。把它作为作用域
		// 传给这次触发：verifier 由此只可能读到、写到自己这一条，而不是靠它在全局
		// 候选列表里"挑一条"——多个任务并发登记时，那种挑法会把 B 任务的漏洞认成
		// A 任务的验证结论。
		scopedFinding := int64(0)
		if e.Tool == "report_finding" {
			scopedFinding = findingIDFromReportOutput(e.ToolOutput)
		}
		for _, tr := range want {
			if !containsFold(tr.ToolNames, e.Tool) {
				continue
			}
			sc.s.StartTriggeredRunScoped(tr.AgentKey, fmt.Sprintf("工具触发 · %s · task#%d", e.Tool, e.TaskID), tr.ToolCallMessage+msgCtx, e.TaskID, scopedFinding, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = sc.pg.SetSchedState(schedKeyLastToolCall, strconv.FormatInt(maxID, 10))
}

// findingIDFromReportOutput pulls the standalone finding id out of a report_finding
// tool result. The result is a human first line followed by the JSON payload:
//
//	finding recorded: <node id>
//	{"finding_id":"<id>", ...}
//
// Two traps. The number on the human line is the EXPLORATION NODE id — a different
// handle, the one update_finding_report takes — so it is deliberately not what this
// reads. And RecordedFinding tags FindingID `json:"finding_id,string"`, so the payload
// carries the id as a quoted string; decoding it into a plain int64 fails silently and
// drops the scope. Returns 0 for anything it cannot parse, which leaves the fire
// unscoped rather than binding it to a wrong id.
func findingIDFromReportOutput(out string) int64 {
	i := strings.IndexByte(out, '\n')
	if i < 0 {
		return 0
	}
	var payload struct {
		FindingID int64 `json:"finding_id,string"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out[i+1:])), &payload); err != nil {
		return 0
	}
	return payload.FindingID
}

// containsFold reports whether name is in set (case-insensitive).
func containsFold(set []string, name string) bool {
	for _, s := range set {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// trunc caps s to max runes, appending an ellipsis + original length when cut.
func trunc(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + fmt.Sprintf("…(已截断,共 %d 字)", len(r))
}

func (sc *Scheduler) mustState(key string) string {
	v, _ := sc.pg.GetSchedState(key)
	return v
}

func (sc *Scheduler) firedGoalSet() map[int64]bool {
	out := map[int64]bool{}
	raw := sc.mustState(schedKeyFiredGoals)
	if raw == "" {
		return out
	}
	var ids []int64
	if json.Unmarshal([]byte(raw), &ids) == nil {
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

func (sc *Scheduler) saveFiredGoalSet(set map[int64]bool) {
	ids := make([]int64, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	b, _ := json.Marshal(ids)
	if err := sc.pg.SetSchedState(schedKeyFiredGoals, string(b)); err != nil {
		log.Printf("[scheduler] save fired goals failed: %v", err)
	}
}
