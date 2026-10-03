package evidence

import (
	"testing"
	"time"
)

func TestReconstructTimeline(t *testing.T) {
	baseTime := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }

	content := []byte("malware payload bytes")
	ev := NewEvidence("ev-001", "dev-42", "agent-collector", "FILE_EXTRACTION", "evt-99", content, clock)

	// Add access and seal custody actions
	ev.RecordAccess("investigator-bob", func() time.Time { return baseTime.Add(20 * time.Minute) })
	ev.Seal("evidence-officer-alice", func() time.Time { return baseTime.Add(30 * time.Minute) })

	// Telemetry events
	telemetry := []TimelineEvent{
		{
			Timestamp: baseTime.Add(-10 * time.Minute),
			Source:    "telemetry",
			Actor:     "endpoint-agent",
			Action:    "PROCESS_LAUNCH",
			Target:    "powershell.exe",
			Verified:  true,
		},
		{
			Timestamp: baseTime.Add(5 * time.Minute),
			Source:    "telemetry",
			Actor:     "endpoint-agent",
			Action:    "NETWORK_OUTBOUND",
			Target:    "198.51.100.55:443",
			Verified:  true,
		},
	}

	// Command events
	commands := []TimelineEvent{
		{
			Timestamp: baseTime.Add(15 * time.Minute),
			Source:    "command",
			Actor:     "secops-admin",
			Action:    "QUARANTINE",
			Target:    "dev-42",
			Verified:  true,
		},
	}

	// Reconstruct timeline
	tl := ReconstructTimeline(ev, telemetry, commands)

	// Expect 3 custody + 2 telemetry + 1 command = 6 total events
	if len(tl.Events) != 6 {
		t.Fatalf("expected 6 timeline events, got %d", len(tl.Events))
	}

	// Verify chronological order
	for i := 0; i < len(tl.Events)-1; i++ {
		if tl.Events[i].Timestamp.After(tl.Events[i+1].Timestamp) {
			t.Fatalf("events not sorted chronologically at index %d: %v after %v",
				i, tl.Events[i].Timestamp, tl.Events[i+1].Timestamp)
		}
	}

	// Verify first event is the initial telemetry launch
	if tl.Events[0].Action != "PROCESS_LAUNCH" {
		t.Errorf("expected first event to be PROCESS_LAUNCH, got %s", tl.Events[0].Action)
	}

	// Verify custody events are marked verified
	custodyEvents := tl.FilterBySource("custody")
	if len(custodyEvents) != 3 {
		t.Fatalf("expected 3 custody events, got %d", len(custodyEvents))
	}
	for _, ce := range custodyEvents {
		if !ce.Verified {
			t.Errorf("expected verified custody event, got false for %+v", ce)
		}
	}

	// Test time range filtering
	rangeEvents := tl.FilterTimeRange(baseTime, baseTime.Add(16*time.Minute))
	// Should include: genesis COLLECTED (baseTime), telemetry NETWORK_OUTBOUND (+5m), command QUARANTINE (+15m)
	if len(rangeEvents) != 3 {
		t.Errorf("expected 3 events in time range, got %d", len(rangeEvents))
	}
}

func TestReconstructTimeline_TamperedCustody(t *testing.T) {
	baseTime := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	ev := NewEvidence("ev-002", "dev-42", "agent-collector", "DUMP", "evt-1", []byte("data"), func() time.Time { return baseTime })
	ev.RecordAccess("analyst-1", func() time.Time { return baseTime.Add(5 * time.Minute) })

	// Tamper with second entry hash
	ev.Custody[1].Hash = "tampered-hash-0000"

	tl := ReconstructTimeline(ev, nil, nil)
	if len(tl.Events) != 2 {
		t.Fatalf("expected 2 custody events, got %d", len(tl.Events))
	}

	// First event (before tampering) should be verified
	if !tl.Events[0].Verified {
		t.Error("expected first custody entry before tamper point to be verified")
	}

	// Tampered entry should be marked unverified
	if tl.Events[1].Verified {
		t.Error("expected tampered entry to be unverified")
	}
}
