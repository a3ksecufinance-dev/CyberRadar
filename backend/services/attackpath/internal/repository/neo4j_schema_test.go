package repository

import (
	"os"
	"strings"
	"testing"
)

// The migration file and EnsureSchema must not drift apart.
//
// Both exist for a reason: the file is what an operator applies and reviews,
// EnsureSchema is what keeps a fresh deployment correct without one. Two copies
// of a schema that are allowed to disagree are how a constraint ends up present
// in one environment and absent in the next — which, for the uniqueness keys
// that mirror PostgreSQL's, means duplicate nodes nobody notices until the
// traversal walks the same asset twice.
func TestTheMigrationFileMatchesEnsureSchema(t *testing.T) {
	const path = "../../../../migrations/neo4j/000001_attack_graph.cypher"

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// Comments are stripped before the split, not after: a prose semicolon in
	// the header would otherwise read as the end of a statement.
	var code []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "//") {
			code = append(code, line)
		}
	}
	var fromFile []string
	for _, stmt := range strings.Split(strings.Join(code, " "), ";") {
		if stmt = strings.Join(strings.Fields(stmt), " "); stmt != "" {
			fromFile = append(fromFile, stmt)
		}
	}

	if len(fromFile) != len(schemaStatements) {
		t.Fatalf("the file has %d statement(s), EnsureSchema runs %d:\n  file: %v\n  code: %v",
			len(fromFile), len(schemaStatements), fromFile, normalised(schemaStatements))
	}
	for i, want := range normalised(schemaStatements) {
		if fromFile[i] != want {
			t.Errorf("statement %d differs:\n  file: %s\n  code: %s", i+1, fromFile[i], want)
		}
	}
}

// normalised collapses the indentation the Go literals carry so the two can be
// compared as statements rather than as formatting.
func normalised(stmts []string) []string {
	out := make([]string, 0, len(stmts))
	for _, stmt := range stmts {
		out = append(out, strings.Join(strings.Fields(stmt), " "))
	}
	return out
}
