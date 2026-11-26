package db

import "testing"

// runRetest drives one retest session to its terminal state with the given
// staged verdict, using the same calls the server makes, and returns its ID.
func runRetest(t *testing.T, d *DB, fid int64, verdict, summary, finish string) int64 {
	t.Helper()
	ctx := t.Context()
	r, c, _, err := d.CreateFindingRetest(ctx, fid, "")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.StartFindingRetest(ctx, r.ID); err != nil || !ok {
		t.Fatalf("start retest: ok=%v err=%v", ok, err)
	}
	if verdict != "" {
		if err := d.RecordFindingRetestResult(ctx, c.ID, verdict, summary, "retest evidence"); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.FinishFindingRetest(r.ID, finish, ""); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func verificationOf(t *testing.T, d *DB, fid int64) (status string, poe int, note string) {
	t.Helper()
	if err := d.QueryRow(`SELECT verification_status, poe_level, verification_note FROM findings WHERE id=$1`, fid).
		Scan(&status, &poe, &note); err != nil {
		t.Fatal(err)
	}
	return
}

func TestRetestModelVerdictsDoNotPromoteVerificationOrDisposition(t *testing.T) {
	for _, verdict := range []string{"reproduced", "fixed"} {
		t.Run(verdict, func(t *testing.T) {
			d, fid := retestDB(t)
			if _, err := d.SetFindingStatus(fid, FindingInProgress); err != nil {
				t.Fatal(err)
			}
			if err := d.SetFindingVerification(fid, VerificationBlocked, 2, "independent evidence missing"); err != nil {
				t.Fatal(err)
			}
			rid := runRetest(t, d, fid, verdict, "model-authored retest conclusion", "completed")
			status, poe, note := verificationOf(t, d, fid)
			if status != VerificationBlocked || poe != 2 || note != "independent evidence missing" {
				t.Fatalf("%s verdict promoted verification: status=%s poe=%d note=%q", verdict, status, poe, note)
			}
			f, err := d.GetFinding(fid)
			if err != nil || f == nil || f.Status != FindingInProgress {
				t.Fatalf("%s verdict changed human disposition: finding=%+v err=%v", verdict, f, err)
			}
			var gotVerdict, gotStatus string
			if err := d.QueryRow(`SELECT verdict,status FROM finding_retests WHERE id=$1`, rid).Scan(&gotVerdict, &gotStatus); err != nil {
				t.Fatal(err)
			}
			if gotVerdict != verdict || gotStatus != "completed" {
				t.Fatalf("formal verdict not preserved: verdict=%q status=%q", gotVerdict, gotStatus)
			}
		})
	}
}

func TestRetestInconclusiveDoesNotDowngradeVerified(t *testing.T) {
	d, fid := retestDB(t)
	if err := d.SetFindingVerification(fid, VerificationVerified, 3, ""); err != nil {
		t.Fatal(err)
	}
	runRetest(t, d, fid, "inconclusive", "target unreachable from the retest session", "completed")
	status, poe, note := verificationOf(t, d, fid)
	if status != VerificationVerified || poe != 3 || note != "" {
		t.Fatalf("verified finding after inconclusive: status=%s poe=%d note=%q", status, poe, note)
	}
}

func TestRetestFailedOrStoppedLeavesVerificationUnchanged(t *testing.T) {
	for _, finish := range []string{"failed", "stopped"} {
		t.Run(finish, func(t *testing.T) {
			d, fid := retestDB(t)
			if err := d.SetFindingVerification(fid, VerificationNotAssessed, 3, "earlier note"); err != nil {
				t.Fatal(err)
			}
			// A verdict staged before the session was cut off must not count.
			runRetest(t, d, fid, "reproduced", "staged before interruption", finish)
			status, poe, note := verificationOf(t, d, fid)
			if status != VerificationNotAssessed || poe != 3 || note != "earlier note" {
				t.Fatalf("after %s: status=%s poe=%d note=%q", finish, status, poe, note)
			}
		})
	}
}

func TestRetestLeavesNotAssessedAndBlockedUnchanged(t *testing.T) {
	for _, from := range []string{VerificationNotAssessed, VerificationBlocked} {
		t.Run(from, func(t *testing.T) {
			d, fid := retestDB(t)
			if err := d.SetFindingVerification(fid, from, 0, ""); err != nil {
				t.Fatal(err)
			}
			runRetest(t, d, fid, "reproduced", "model says reproduced", "completed")
			if status, _, _ := verificationOf(t, d, fid); status != from {
				t.Fatalf("from %s after reproduced: status=%s", from, status)
			}
		})
	}
}
