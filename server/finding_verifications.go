package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// verifierToolCallMessage is the trigger message the scheduler hands the verifier
// when a worker calls report_finding. It has to be self-sufficient: unlike the
// retester, a triggered run has no server-owned conversation row tying it to one
// finding, so the agent is told how to find its worklist instead of being handed an id.
const verifierToolCallMessage = "上面刚有一个漏洞被 report_finding 登记。请先用 list_candidate_findings 读回待验证的漏洞（含原始证据），" +
	"再用与原始证据【不同】的路径或独立命令独立复现一次（做对照、换入口、换观察面），" +
	"最后用 record_finding_verification(finding_id, verdict, summary, evidence) 落结论：" +
	"复现成功用 confirmed，尝试后未能复现用 unverified，无法判定用 inconclusive。" +
	"禁止把原始证据换个措辞复述当作验证通过；拿不准就用 inconclusive。"

// findingVerificationTools are the verifier agent's two tools. They are the only
// writers of finding_verifications.
func (s *Server) findingVerificationTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("list_candidate_findings",
			"列出尚未通过独立验证的漏洞（status=candidate），含原始证据，供你挑选要复现的那一条。传入 finding_id 时只返回该条。",
			objSchema(map[string]any{
				"finding_id": map[string]any{"type": "integer", "description": "可选：只看这一条漏洞"},
				"limit":      map[string]any{"type": "integer", "description": "可选：最多返回几条，默认 20，上限 100"},
			}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				if s.m.pg == nil {
					return actool.Errorf("数据库不可用"), nil
				}
				var a struct {
					FindingID int64 `json:"finding_id"`
					Limit     int   `json:"limit"`
				}
				_ = json.Unmarshal(in, &a)
				items, err := s.m.pg.CandidateFindings(a.Limit)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				out := make([]map[string]any, 0, len(items))
				for _, f := range items {
					if a.FindingID > 0 && f.ID != a.FindingID {
						continue
					}
					out = append(out, map[string]any{
						"finding_id": f.ID,
						"vulnclass":  f.VulnClass,
						"name":       f.Name,
						"severity":   f.Severity,
						"summary":    f.Summary,
						// The original evidence is what the verifier must NOT merely
						// restate, so it is handed over verbatim — capped so a giant PoC
						// cannot swamp the run.
						"evidence": truncateRunes(f.Evidence, 4000),
						"status":   f.Status,
					})
				}
				if a.FindingID > 0 && len(out) == 0 {
					return actool.Errorf(fmt.Sprintf("漏洞 #%d 不存在，或已不是待验证(candidate)状态——可能已通过验证或已被人工处置", a.FindingID)), nil
				}
				return jsonResult(map[string]any{"candidates": out, "count": len(out)})
			}),

		wrTool("record_finding_verification",
			"为指定的漏洞保存本次独立验证的唯一结论。只有 confirmed 会把漏洞状态提升为已确认；unverified / inconclusive 保持待验证不变。必须提供本次实际复现的证据，无法判定时写明阻塞原因。",
			objSchema(map[string]any{
				"finding_id": map[string]any{"type": "integer", "description": "要落结论的漏洞 id（来自 list_candidate_findings）"},
				"verdict":    map[string]any{"type": "string", "enum": []string{db.VerdictConfirmed, db.VerdictUnverified, db.VerdictInconclusive}, "description": "confirmed=独立复现成功；unverified=尝试后未能复现；inconclusive=无法判定"},
				"summary":    strParam("本次验证结论摘要"),
				"evidence":   strParam("Markdown：你本次实际执行的复现步骤、观察到的原始回显、与原始证据的不同之处、对照结果；无法判定则写明已检查内容与阻塞原因"),
			}, "finding_id", "verdict", "summary", "evidence"),
			func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				if s.m.pg == nil {
					return actool.Errorf("数据库不可用"), nil
				}
				var a struct {
					FindingID int64  `json:"finding_id"`
					Verdict   string `json:"verdict"`
					Summary   string `json:"summary"`
					Evidence  string `json:"evidence"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if utf8.RuneCountInString(a.Evidence) > 20000 {
					return actool.Errorf("evidence 最多 20000 个字符"), nil
				}
				var convID *int64
				if id := intercept.ConvIDFromContext(ctx); id > 0 {
					convID = &id
				}
				if err := s.m.pg.RecordFindingVerification(ctx, a.FindingID, a.Verdict,
					strings.TrimSpace(a.Summary), strings.TrimSpace(a.Evidence), db.VerifierAgentKey, convID); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"saved": true, "finding_id": a.FindingID, "verdict": a.Verdict})
			}),
	}
}

// truncateRunes caps s at n runes without splitting a multi-byte character.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…（已截断）"
}

// verifierBoundTools are the tools bound to the verifier agent at seed time. Kept as a
// named list because it is a contract with hostTools(): binding a name that hostTools()
// does not produce leaves the agent with a tool it can never call, and the model then
// degrades into echoing the tool's name as a shell command instead of invoking it.
// TestHostToolsCoverVerifierBindings enforces that.
var verifierBoundTools = []string{
	"list_candidate_findings", "record_finding_verification",
	// 共享经验的「不同的声音」：比对新观察与既有经验，否证时删条目。
	"list_lessons", "quash_lesson",
	"get_task_node_detail", "list_task_findings",
	"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
	"get_task_graph",
}

// seedVerifierAgent provisions the "漏洞验证" agent plus its report_finding trigger.
// Mirrors seedReporterAgent: builtin=false (editable/deletable in the UI), guarded by a
// one-shot settings flag so a deliberate deletion is not undone on the next restart.
//
// It must be seeded for the verification gate in prove_goal to have anything to rely on:
// with no enabled verifier, nothing ever promotes a candidate finding, which is exactly
// why prove_goal falls back to the pre-verification behaviour in that case.
func (s *Server) seedVerifierAgent() {
	const flag = "verifier_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次

	for _, t := range s.findingVerificationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings, _ := json.Marshal([]string{db.VerifierAgentKey})
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			log.Printf("[verifier] 注册工具 %s 失败: %v", t.Name(), err)
			return
		}
	}
	// 经验库的「不同的声音」工具（见 lesson_verify.go）。
	for _, t := range s.lessonConflictTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings, _ := json.Marshal([]string{db.VerifierAgentKey})
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			log.Printf("[verifier] 注册经验工具 %s 失败: %v", t.Name(), err)
			return
		}
	}

	if exist, _ := s.m.pg.GetAgentByKey(db.VerifierAgentKey); exist != nil {
		return // key 已被占用(用户手建过)——不覆盖
	}
	a, err := s.m.pg.CreateAgent(db.VerifierAgentKey, "漏洞验证",
		"漏洞独立验证：发现漏洞时自动触发，用与首次不同的路径独立复现一次，判定真伪并回写结论。")
	if err != nil {
		log.Printf("[verifier] 创建 agent 失败: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.VerifierDefaultPrompt); err != nil {
		log.Printf("[verifier] seed prompt 失败: %v", err)
	}
	// 一漏洞一次验证、多个 finding 并发各验各的：merge 必须为 none，否则一波 finding
	// 会被合并成一次运行，并行就失去意义。
	if err := s.m.pg.SetAgentTriggerBehavior(db.VerifierAgentKey, "parallel", "none", 5); err != nil {
		log.Printf("[verifier] 设置触发运行策略失败: %v", err)
	}
	// 读原始证据所需的只读工具（复现本身用 chat agent 自带的 Bash / WebFetch）。
	if err := s.m.pg.AddAgentToToolBinding(db.VerifierAgentKey, verifierBoundTools); err != nil {
		log.Printf("[verifier] 绑定工具失败: %v", err)
	}
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        db.VerifierAgentKey,
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: verifierToolCallMessage,
	}); err != nil {
		log.Printf("[verifier] 创建触发器失败: %v", err)
	}
	// 经验矛盾触发器：observed fact 落图时唤醒 verifier 比对经验库（不同的声音）。
	// 只对 observed 级触发——inferred 是猜想，拿猜想否证经验是让噪音开门。
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:   db.VerifierAgentKey,
		Enabled:    true,
		OnToolCall: true,
		ToolNames:  []string{"record_fact"},
		ToolCallMessage: lessonConflictMessage("（见下方触发原文中的 record_fact 调用参数）") +
			"——读取最近一次 record_fact 的 summary 与 confidence，仅 confidence=observed 时比对；inferred 的直接忽略本轮。",
	}); err != nil {
		log.Printf("[verifier] 创建经验触发器失败: %v", err)
	}
	log.Printf("[verifier] 已预置「漏洞验证」agent + finding/经验两个触发器")
}

// listFindingVerifications exposes the audit trail: what was verified, by whom, and
// with what evidence.
func (s *Server) listFindingVerifications(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	items, err := pg.FindingVerifications(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"verifications": items})
}
