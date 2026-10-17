package server

import (
	"testing"
	"time"
)

// TestNotifyWorkerCoalescesAndNeverBlocks pins the channel contract the worker pool
// relies on: a burst of wake-ups collapses into a single pending signal, and sending
// never blocks the caller (a planner round or another worker must not stall on it).
func TestNotifyWorkerCoalescesAndNeverBlocks(t *testing.T) {
	task := &Task{ID: "t1", workerNotify: make(chan struct{}, 1)}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			task.NotifyWorker()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NotifyWorker blocked; it must drop rather than wait for a receiver")
	}

	select {
	case <-task.workerNotify:
	default:
		t.Fatal("no wake-up buffered after 1000 sends")
	}
	select {
	case <-task.workerNotify:
		t.Fatal("wake-ups did not coalesce into one pending signal")
	default:
	}
}

// TestNotifyWorkerNilChannelIsSafe covers the Task values several tests build without
// a wake channel (production always goes through taskFromPG). A nil channel must be a
// silent no-op, never a block or a panic.
func TestNotifyWorkerNilChannelIsSafe(t *testing.T) {
	task := &Task{ID: "t1"}
	done := make(chan struct{})
	go func() {
		task.NotifyWorker()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NotifyWorker blocked on a nil workerNotify channel")
	}
}

// TestResumeWakesWorkerPool guards one ignition point: resuming a paused task must wake
// the pool, or workers would keep idling until their fallback tick while claimable
// intents sit in the frontier.
func TestResumeWakesWorkerPool(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t1", notify: make(chan struct{}, 1), workerNotify: make(chan struct{}, 1)}
	e.paused.Store(task.ID, true)

	e.Resume(task)

	select {
	case <-task.workerNotify:
	default:
		t.Fatal("Resume did not wake the worker pool")
	}
}

// TestResumeStillSignalsPlanner keeps the pre-existing planner wake on the resume path
// intact — the worker signal is additive, not a replacement.
func TestResumeStillSignalsPlanner(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t1", notify: make(chan struct{}, 1), workerNotify: make(chan struct{}, 1)}
	e.paused.Store(task.ID, true)

	e.Resume(task)

	select {
	case <-task.notify:
	default:
		t.Fatal("Resume no longer wakes the planner")
	}
}
