package kafka

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Which services must not lose an event, and which may.
//
// This is a source-level check for the same reason internal/pkg/deploycheck
// is one: the choice lives in a `main.go` that no unit test constructs, and it
// is one token long. The rule engine carried the wrong one — skip whatever
// arrived while the SIEM was restarting — for as long as it existed, next to a
// pipeline worker that carried the right one, and the difference is invisible
// at a glance. A new service copied from a neighbour inherits whichever
// neighbour it was copied from.
//
// A service absent from both lists is deliberate: it does not use the
// platform's consumer.
var (
	mustNotLoseAnEvent = []string{
		"siem",     // the rule engine: a skipped window is an attack that did not happen
		"ueba",     // baselines built on a gap understate the activity
		"pipeline", // the store of record for every event
	}
	mayStartAtTheEnd = []string{
		"asset", "pam", "ti", // consumers of current state
		"soar",           // acts: replaying an alert re-runs its playbook
		"apifw",          // webhook delivery
		"knowledgegraph", // projection, rebuilt from PostgreSQL
	}
)

var startOffsetCall = regexp.MustCompile(`StartOffset:\s*(?:pkgkafka\.)?(\w+)`)

func TestEveryConsumerSaysWhereItStartsAndWhyItMatters(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("find the backend root: %v", err)
	}

	check := func(service, want string) {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(root, "services", service, "cmd", "server", "main.go")) //nolint:gosec // a path this test built
		if err != nil {
			// the pipeline is a worker, not a server
			body, err = os.ReadFile(filepath.Join(root, "services", service, "cmd", "worker", "main.go")) //nolint:gosec // same
			if err != nil {
				t.Errorf("%s: no main.go to read: %v", service, err)
				return
			}
		}
		found := startOffsetCall.FindAllStringSubmatch(string(body), -1)
		if len(found) == 0 {
			t.Errorf("%s: no StartOffset at all; it would default to %s, which is a choice "+
				"nobody made", service, "OnlyNewEvents")
			return
		}
		for _, m := range found {
			switch m[1] {
			case want:
			case "FromTheBeginning", "OnlyNewEvents":
				t.Errorf("%s: starts at %s, want %s — see the constants in this package for "+
					"what that does to the events that arrived while it was down", service, m[1], want)
			default:
				t.Errorf("%s: StartOffset is %q; use kafka.FromTheBeginning or "+
					"kafka.OnlyNewEvents so the choice reads as one", service, m[1])
			}
		}
	}

	for _, s := range mustNotLoseAnEvent {
		check(s, "FromTheBeginning")
	}
	for _, s := range mayStartAtTheEnd {
		check(s, "OnlyNewEvents")
	}
}

// repoRoot walks up to the directory holding go.work.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// And the two constants must stay distinct, since the whole check rests on a
// name rather than on the value behind it.
func TestTheTwoStartOffsetsAreNotTheSameThing(t *testing.T) {
	if FromTheBeginning == OnlyNewEvents {
		t.Fatal("the two constants are equal, so every call site above asserts nothing")
	}
}
