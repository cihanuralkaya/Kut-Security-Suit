package evidence

import (
	"fmt"
	"sort"
	"time"
)

// TimelineEvent represents a discrete event in a forensic investigation timeline.
type TimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "custody", "telemetry", "command"
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Hash      string    `json:"hash,omitempty"`
	Verified  bool      `json:"verified"`
	Detail    string    `json:"detail,omitempty"`
}

// Timeline encapsulates a chronological list of correlated forensic events.
type Timeline struct {
	Events []TimelineEvent `json:"events"`
}

// Sort orders the timeline events chronologically.
func (t *Timeline) Sort() {
	sort.Slice(t.Events, func(i, j int) bool {
		return t.Events[i].Timestamp.Before(t.Events[j].Timestamp)
	})
}

// Add appends a timeline event.
func (t *Timeline) Add(evt TimelineEvent) {
	t.Events = append(t.Events, evt)
}

// FilterBySource returns a sub-timeline containing only events from a given source.
func (t *Timeline) FilterBySource(source string) []TimelineEvent {
	var filtered []TimelineEvent
	for _, e := range t.Events {
		if e.Source == source {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// FilterTimeRange returns events occurring within [start, end].
func (t *Timeline) FilterTimeRange(start, end time.Time) []TimelineEvent {
	var filtered []TimelineEvent
	for _, e := range t.Events {
		if (e.Timestamp.Equal(start) || e.Timestamp.After(start)) &&
			(e.Timestamp.Equal(end) || e.Timestamp.Before(end)) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// ReconstructTimeline integrates chain-of-custody logs from an Evidence record
// with correlated telemetry and command execution events into a single verified timeline.
func ReconstructTimeline(ev Evidence, telemetryEvents []TimelineEvent, commandEvents []TimelineEvent) Timeline {
	tl := Timeline{}

	// 1. Verify custody chain integrity
	chainOk, brokenAt := ev.Verify()

	// 2. Add custody entries
	for i, c := range ev.Custody {
		// A custody entry is marked verified only if the custody verification passes
		// or if the break occurred strictly after this entry.
		verified := chainOk || (brokenAt >= 0 && i < brokenAt)

		tl.Add(TimelineEvent{
			Timestamp: c.At,
			Source:    "custody",
			Actor:     c.Actor,
			Action:    c.Action,
			Target:    fmt.Sprintf("evidence:%s#seq-%d", ev.ID, c.Seq),
			Hash:      c.Hash,
			Verified:  verified,
			Detail:    fmt.Sprintf("prev_hash=%s", c.PrevHash),
		})
	}

	// 3. Add telemetry events
	for _, te := range telemetryEvents {
		if te.Source == "" {
			te.Source = "telemetry"
		}
		tl.Add(te)
	}

	// 4. Add command events
	for _, ce := range commandEvents {
		if ce.Source == "" {
			ce.Source = "command"
		}
		tl.Add(ce)
	}

	// 5. Sort chronologically
	tl.Sort()

	return tl
}
