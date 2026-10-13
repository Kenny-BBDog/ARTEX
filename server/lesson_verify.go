package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/memory"
	actool "github.com/Autumn-27/norma/tool"
)

// lesson_verify.go — the adversarial check on the shared brain ("the different voice").
//
// The write side (lessons.go) auto-promotes confidence='observed' facts, because an
// observation cannot lie about WHAT happened. But it can lie about REPEATABILITY:
// two tasks on different deployments of the same stack yield opposite observations
// ("JWT accepts alg:none" here vs "JWT rejects alg:none" there), and when they
// collide the newer observation must not silently overwrite the older one — that
// would make the brain flatter whichever task ran last.
//
// So the check is event-driven and adversarial in the same shape as the finding
// verifier: when a task records an observed fact that contradicts an existing
// entry, the verifier (a separate agent) wakes with both statements in front of it
// and decides. It has exactly one destructive tool: quash a lesson it judges wrong
// (delete the file). Silence keeps the entry. This is deliberately NOT the model
// that wrote the entry judging its own entry — 一个 agent 可能出错，不可能全部
// agent 都出错，需要有 agent 能有不同的声音.

// lessonConflictTools are bound to the verifier agent alongside its finding tools.
func (s *Server) lessonConflictTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("list_lessons",
			"列出共享经验库的条目（name/描述/内容），供比对一条新观察与既有经验是否矛盾。可选 query 按关键词过滤。",
			objSchema(map[string]any{
				"query": map[string]any{"type": "string", "description": "可选：按关键词过滤（名称+描述+内容子串匹配）"},
				"limit": map[string]any{"type": "integer", "description": "可选：最多返回几条，默认 30，上限 100"},
			}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				store := memory.NewStore(memoryDirPath(s.m.dir))
				mems, err := store.Scan()
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				var a struct {
					Query string `json:"query"`
					Limit int    `json:"limit"`
				}
				_ = json.Unmarshal(in, &a)
				if a.Limit <= 0 || a.Limit > 100 {
					a.Limit = 30
				}
				out := make([]map[string]any, 0, len(mems))
				for _, m := range mems {
					if a.Query != "" &&
						!strings.Contains(m.Name, a.Query) &&
						!strings.Contains(m.Description, a.Query) &&
						!strings.Contains(m.Content, a.Query) {
						continue
					}
					out = append(out, map[string]any{
						"name":        m.Name,
						"description": m.Description,
						"type":        string(m.Type),
						"content":     m.Content,
					})
					if len(out) >= a.Limit {
						break
					}
				}
				return jsonResult(map[string]any{"lessons": out, "count": len(out)})
			}),

		wrTool("quash_lesson",
			"删除一条被新证据否证的经验条目。仅当新 observed 观察与该条目直接矛盾、且你独立判断新观察更可信时使用；删除前必须在 evidence 里写明矛盾点与两边的证据。拿不准就别删——错误的经验只是低效，被误删的正确经验是盲区。",
			objSchema(map[string]any{
				"name":     map[string]any{"type": "string", "description": "要删除的条目名（来自 list_lessons，全名精确匹配）"},
				"evidence": map[string]any{"type": "string", "description": "矛盾点 + 两边证据的对比；进入审计日志"},
			}, "name", "evidence"),
			func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					Name     string `json:"name"`
					Evidence string `json:"evidence"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				store := memory.NewStore(memoryDirPath(s.m.dir))
				mems, err := store.Scan()
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				// Exact full-name match (not slug): a typo'd name must error rather
				// than silently delete a prefix-neighbor.
				name := strings.TrimSpace(a.Name)
				found := false
				for _, m := range mems {
					if m.Name != name {
						continue
					}
					found = true
					if err := os.Remove(m.Path); err != nil {
						return actool.Errorf(fmt.Sprintf("删除失败: %v", err)), nil
					}
					break
				}
				if !found {
					return actool.Errorf(fmt.Sprintf("经验条目 %q 不存在——用 list_lessons 复制全名", name)), nil
				}
				if s.m.pg == nil {
					return actool.Errorf("数据库不可用"), nil
				}
				if _, err := s.m.pg.Exec(`INSERT INTO activity(exploration_id, node_id, kind, worker, summary, detail)
					VALUES (0, NULL, 'lesson_quashed', $1, $2, $3)`,
					db.VerifierAgentKey, "经验条目被否证删除: "+name, strings.TrimSpace(a.Evidence)); err != nil {
					// 审计失败不回滚删除 —— 一个没有日志的删除仍好过一个被静默覆盖的事实。
					log.Printf("[lessons] 审计日志写入失败（删除已生效）: %v", err)
				}
				log.Printf("[lessons] verifier 否证删除条目 %q：%s", name, oneline(a.Evidence, 120))
				return jsonResult(map[string]any{"quashed": name})
			}),
	}
}

// lessonConflictMessage is the trigger message for record_fact conflicts. Like the
// finding trigger, it must be self-sufficient.
func lessonConflictMessage(factSummary string) string {
	return "一条新的 observed 观察似乎与共享经验库的既有条目矛盾。请用 list_lessons 找到相关条目，" +
		"比对这条观察与既有条目的内容后独立判断谁更可信，最后决定：矛盾确凿且新观察更可信 → quash_lesson(name, evidence)；" +
		"只是措辞不同/面向不同部署（比如不同版本的靶场）→ 不动（经验条目已写来源任务，误删正确经验是盲区）。" +
		"新观察摘要：" + clip(factSummary, 300)
}

// oneline caps a string to one line for log output.
func oneline(s string, max int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}
