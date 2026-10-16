// Package deploycheck holds no code. It holds the tests that keep the two ways
// of running this platform from drifting apart: deployments/docker-compose.yml
// and scripts/dev-local.sh, which exists for machines where Docker cannot pull
// an image.
//
// A service added to one and not the other is not a build failure — it is a
// service that simply does not start, on whichever of the two the person
// deploying happens to use.
package deploycheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", rel)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

// composeServices are the services docker-compose builds, with the port each
// one is given.
func composeServices(t *testing.T) map[string]string {
	t.Helper()
	compose := repoFile(t, "deployments/docker-compose.yml")

	out := map[string]string{}
	name := regexp.MustCompile(`(?m)^      - SERVICE_NAME=([a-z0-9-]+)\s*$`)
	port := regexp.MustCompile(`(?m)^      - SERVICE_PORT=(\d+)\s*$`)
	names := name.FindAllStringSubmatch(compose, -1)
	for _, m := range names {
		// The port follows the name in every service block; find the first one
		// after this name.
		idx := strings.Index(compose, m[0])
		rest := compose[idx:]
		if p := port.FindStringSubmatch(rest); p != nil {
			out[m[1]] = p[1]
		} else {
			out[m[1]] = ""
		}
	}
	return out
}

// localServices are the services the local runner starts, from its own table.
func localServices(t *testing.T) map[string]string {
	t.Helper()
	script := repoFile(t, "scripts/dev-local.sh")

	start := strings.Index(script, "SERVICES=(")
	if start < 0 {
		t.Fatal("scripts/dev-local.sh has no SERVICES table")
	}
	end := strings.Index(script[start:], "\n)")
	if end < 0 {
		t.Fatal("scripts/dev-local.sh: the SERVICES table is not closed")
	}

	out := map[string]string{}
	entry := regexp.MustCompile(`"([a-z0-9-]+):(\d+):([a-z]+)"`)
	for _, m := range entry.FindAllStringSubmatch(script[start:start+end], -1) {
		out[m[1]] = m[2]
	}
	return out
}

// A service in one and not the other does not fail to build. It fails to run,
// on whichever of the two the person deploying happens to use.
func TestTheLocalRunnerStartsEveryServiceComposeDoes(t *testing.T) {
	compose, local := composeServices(t), localServices(t)

	// Two empty sets agree with each other. A parser that stopped finding
	// anything — because a file was reformatted — would make every check here
	// pass while checking nothing.
	if len(compose) < 25 || len(local) < 25 {
		t.Fatalf("parsed %d services from docker-compose and %d from the local runner: "+
			"one of the two files changed shape and these checks stopped checking",
			len(compose), len(local))
	}

	// The pipeline worker and the syslog connector have no HTTP port and are
	// started separately by the runner, so they are not in its port table.
	noPort := map[string]bool{"pipeline-worker": true, "syslog-connector": true}

	var missing, extra []string
	for name := range compose {
		if noPort[name] {
			continue
		}
		if _, ok := local[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range local {
		if _, ok := compose[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("docker-compose builds these and scripts/dev-local.sh does not start them: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("scripts/dev-local.sh starts these and docker-compose does not build them: %v", extra)
	}
}

// A port that differs between the two is worse than a missing service: the
// interface's port table names one number, and half the platform answers on
// another depending on how it was started.
func TestThePortsAgree(t *testing.T) {
	compose, local := composeServices(t), localServices(t)
	for name, composePort := range compose {
		localPort, ok := local[name]
		if !ok || composePort == "" {
			continue
		}
		if composePort != localPort {
			t.Errorf("%s: docker-compose says :%s, scripts/dev-local.sh says :%s", name, composePort, localPort)
		}
	}
}

// The interface reaches each service by port from its own table. A number that
// disagrees with the deployment is a 404 no page can recover from.
func TestTheInterfacePortTableAgreesToo(t *testing.T) {
	compose := composeServices(t)
	api := repoFile(t, "../frontend/src/lib/api.ts")

	start := strings.Index(api, "const PORTS:")
	if start < 0 {
		t.Fatal("frontend/src/lib/api.ts has no PORTS table")
	}
	end := strings.Index(api[start:], "}")
	table := api[start : start+end]

	entry := regexp.MustCompile(`([a-z]+):\s*(\d+)`)
	fromAPI := map[string]string{}
	for _, m := range entry.FindAllStringSubmatch(table, -1) {
		fromAPI[m[1]] = m[2]
	}

	for name, port := range compose {
		// The interface names a service by its domain, without the suffix.
		short := strings.TrimSuffix(name, "-service")
		apiPort, ok := fromAPI[short]
		if !ok || port == "" {
			continue
		}
		if apiPort != port {
			t.Errorf("%s: the deployment says :%s, the interface calls :%s", name, port, apiPort)
		}
	}
}
