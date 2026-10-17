package agent

import (
	"context"
	"log"
	"strings"

	"github.com/Autumn-27/norma/harness"

	"github.com/Autumn-27/artex/db"
)

// wrapupFactPrefix marks a fact that runWrapupFact wrote on the run's behalf rather
// than the worker recording it as its own conclusion. It rides in the summary because
// that is the only field the planner's situational snapshot carries — a flag buried in
// the payload would not be visible where the judgement is made.
const wrapupFactPrefix = "【收尾】"

// runWrapupFact is the forced write-back: when a run ends without having produced a
// single conclusion for its intent, it files one fact saying how the run ended.
//
// Why this is a mechanism and not a prompt. The wrap-up prompt already asks the worker
// to persist what it found ("这是最后机会：把你已识别但还没写回的内容【全部】落库"), and
// on a good run it does — measured on the Juice Shop run, all three exhausted routes
// yielded facts (2, 8 and 1 respectively) and every one of the 17 terminal intents
// yielded something. But that is advice to a model, and advice is not a guarantee: a run
// that ends on ReasonCompleted with no text, or dies on a provider error, leaves an
// intent carrying nothing at all. The planner then reads `{state: exhausted}` and has to
// guess whether the direction was ruled out, merely unfinished, or never really tried.
//
// So the invariant this enforces is: a run that reached its own verdict always leaves
// content behind. It is deliberately a safety net rather than a rule — it fires only
// when the intent yielded nothing, so on a run where the worker did write back (the
// normal case) it adds exactly zero nodes.
//
// Best-effort throughout: a failure here must never fail the run.
func runWrapupFact(ctx context.Context, ts *db.ExplorationStore, intent *db.Node, worker string,
	reason harness.TerminalReason, finalText string) (int64, bool) {
	if ts == nil || intent == nil || intent.ID == 0 {
		return 0, false
	}
	if runAbortedByCaller(ctx, reason) {
		return 0, false // 被外部打断，不是这条意图的结论 —— 见 runAbortedByCaller
	}
	n, err := ts.IntentYieldCount(intent.ID)
	if err != nil {
		log.Printf("[wrapup] 意图 #%d 产出计数失败，跳过强制写回: %v", intent.ID, err)
		return 0, false
	}
	if n > 0 {
		return 0, false // 已经留下结论了，不再添一条
	}

	detail := strings.TrimSpace(finalText)
	summary := firstLine(detail, 200)
	if summary == "" {
		// 没有文字总结（空收尾、模型/API 故障、钩子拦停等）。如实记下这次运行是怎么结束的：
		// 「这条方向还没被真正检验」和「这条方向是死路」对规划者是两个完全不同的指令，
		// 而在此之前两者在图上长得一模一样。
		summary = wrapupFactPrefix + "本次运行未留下结论：" + firstLine(terminalReasonHint(reason), 160)
		detail = summary
	} else {
		summary = wrapupFactPrefix + summary
	}

	// 刻意不写 confidence。TaskDepth 用 confidence='observed' 判定「过早放弃」
	// (PrematureExhaustion)，而收尾结论是 run 结束时的一句自述，不是对目标的观测——
	// 标 observed 会让一条从没动过的路线看起来像"已穷尽"，标 inferred 则无端污染计数。
	//
	// 刻意不锚定资产。UntouchedSurface 把「锚了 fact/finding 的资产」算作已触碰，一条收尾
	// 事实并不证明谁真的动过那些资产；锚上去等于把没干过的活记成干过了。
	payload := map[string]any{
		"summary": summary,
		"detail":  detail,
		"wrapup":  true,
	}

	id, err := ts.AddNode(db.KindFact, payload, 5, "confirmed", worker, nil)
	if err != nil {
		log.Printf("[wrapup] 意图 #%d 收尾事实落库失败: %v", intent.ID, err)
		return 0, false
	}
	if err := ts.Link(intent.ID, db.RelYields, id); err != nil {
		log.Printf("[wrapup] 意图 #%d 收尾事实连边失败: %v", intent.ID, err)
		// 节点落下了但没接上边：对"意图是否带着内容"这个不变量而言等于没写成，
		// 所以返回 false —— 调用方不该据此认为这条意图已经有结论了。
		return id, false
	}
	log.Printf("[wrapup] 意图 #%d 本次未留下任何结论，强制写回收尾事实 #%d", intent.ID, id)
	return id, true
}
