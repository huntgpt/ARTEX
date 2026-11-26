package db

import (
	"encoding/json"
	"testing"
)

func TestTaskSupervisionArchiveRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	primary, secondary := supervisorProfiles(t, d)
	task, err := d.CreateTaskWithOptions("archived dual lead", "preserve reviews", TaskCreateOptions{
		Supervisor: &TaskSupervisorConfig{
			Mode:               SupervisorModeDual,
			PrimaryProfileID:   &primary,
			SecondaryProfileID: &secondary,
			CheckpointPolicy:   SupervisorCheckpointEveryRound,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	})

	round, err := d.CreateSupervisorRound(task.ID, "archive_test", map[string]any{"task_id": task.ID}, []SupervisorReviewSeed{
		{LeadRole: "primary", ProfileID: primary, Provider: "codex-cli", Model: "codex-test", AccountLabel: "Codex A"},
		{LeadRole: "secondary", ProfileID: secondary, Provider: "claude-cli", Model: "claude-test", AccountLabel: "Claude B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.StartSupervisorRound(round.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteSupervisorReview(round.ID, "primary", json.RawMessage(`{"assessment":"primary"}`), "primary", "", 10, 5); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteSupervisorReview(round.ID, "secondary", json.RawMessage(`{"assessment":"secondary"}`), "secondary", "", 12, 6); err != nil {
		t.Fatal(err)
	}
	if err = d.SaveSupervisorDecision(round.ID, &primary, json.RawMessage(`{"selected_directions":["primary","secondary"]}`), "merged"); err != nil {
		t.Fatal(err)
	}

	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	job, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FormatVersion != taskArchiveSupervisionFormatVersion ||
		snapshot.DataCounts["task_supervisor_config"] != 1 ||
		snapshot.DataCounts["supervisor_rounds"] != 1 ||
		snapshot.DataCounts["supervisor_reviews"] != 2 ||
		snapshot.DataCounts["supervisor_decisions"] != 1 {
		t.Fatalf("missing supervision archive: version=%d counts=%+v", snapshot.FormatVersion, snapshot.DataCounts)
	}
	if err = d.CompleteTaskArchive(job.ID, snapshot, "/tmp/supervision-fixture.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(job.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}

	restored, err := d.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Supervisor.Mode != SupervisorModeDual ||
		restored.Supervisor.PrimaryProfileID == nil || *restored.Supervisor.PrimaryProfileID != primary ||
		restored.Supervisor.SecondaryProfileID == nil || *restored.Supervisor.SecondaryProfileID != secondary ||
		restored.Supervisor.CheckpointPolicy != SupervisorCheckpointEveryRound {
		t.Fatalf("restored supervisor config = %+v", restored.Supervisor)
	}
	details, err := d.SupervisorRoundDetails(task.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(details) != 1 || details[0].State != "completed" || len(details[0].Reviews) != 2 || details[0].Decision == nil {
		t.Fatalf("restored supervisor round = %+v", details)
	}
}
