package server

import (
	"net/http"
	"strconv"
)

// getTaskOutcome returns one task's post-run summary. The row is written automatically by
// the scheduler once a terminal task has settled (see Scheduler.refreshOutcomes), so a
// missing outcome means "not finished yet, or not settled yet" rather than "not computed".
func (s *Server) getTaskOutcome(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	o, err := pg.GetTaskOutcome(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if o == nil {
		writeJSON(w, 200, map[string]any{
			"outcome": nil,
			"note":    "任务尚未进入终态，或刚结束还未过静置期（结束前在跑的 worker 仍会写回）",
		})
		return
	}
	writeJSON(w, 200, map[string]any{"outcome": o})
}

// listTaskOutcomes returns stored outcomes newest-completed first. This is the read side
// of the metrics flywheel: diff the claimed/confirmed columns against a scenario's known
// findings to get recall and precision.
func (s *Server) listTaskOutcomes(w http.ResponseWriter, r *http.Request) {

	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := pg.ListTaskOutcomes(r.URL.Query().Get("status"), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"outcomes": items, "count": len(items)})
}
