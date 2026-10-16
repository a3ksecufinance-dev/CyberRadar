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
// in one environment and absent in the next — which, for the uniqueness key
// that mirrors PostgreSQL's, means duplicate entities nobody notices until a
// traversal reports the same asset twice.
func TestTheMigrationFileMatchesEnsureSchema(t *testing.T) {
	const path = "../../../../migrations/neo4j/000002_knowledge_graph.cypher"

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

	want := normalised(schemaStatements)
	if len(fromFile) != len(want) {
		t.Fatalf("the file has %d statement(s), EnsureSchema runs %d:\n  file: %v\n  code: %v",
			len(fromFile), len(want), fromFile, want)
	}
	for i := range want {
		if fromFile[i] != want[i] {
			t.Errorf("statement %d differs:\n  file: %s\n  code: %s", i+1, fromFile[i], want[i])
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

// Every relationship type the model declares must be mirrorable. A type the
// model accepts and the mirror refuses would be a relationship PostgreSQL holds
// and Neo4j silently never receives.
func TestEveryModelRelationshipTypeIsMirrorable(t *testing.T) {
	// Transcribed from the validator on UpsertRelationshipRequest, which is
	// what the API actually enforces.
	accepted := strings.Fields(`CONNECTS_TO EXPLOITS TARGETS COMMUNICATES_WITH BELONGS_TO
		RESOLVES_TO ASSOCIATED_WITH ATTRIBUTED_TO MITIGATES HAS_VULNERABILITY INDICATOR_OF USES`)

	for _, relType := range accepted {
		if err := checkRelationshipType(relType); err != nil {
			t.Errorf("the API accepts %s but the mirror refuses it: %v", relType, err)
		}
	}
	if len(relationshipTypes) != len(accepted) {
		t.Errorf("the mirror knows %d types, the API accepts %d", len(relationshipTypes), len(accepted))
	}
	// And an unknown type must be refused before any Cypher is built from it.
	if err := checkRelationshipType("DROP DATABASE neo4j"); err == nil {
		t.Error("an unknown relationship type was accepted")
	}
}
