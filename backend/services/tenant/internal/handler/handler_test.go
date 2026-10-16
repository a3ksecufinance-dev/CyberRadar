package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
	"github.com/cyberradar/platform/services/tenant/internal/service"
)

// The HTTP surface of the tenant service, exercised through the router it
// actually mounts rather than by calling the methods directly.
//
// That matters because most of what can go wrong here is in the wiring and not
// in the handler body: a route mounted at the wrong path, a permission gate
// missing from one verb of four, a domain error mapped to the wrong status, a
// tenant read from the path instead of the token. None of those are visible to
// a test that calls h.Set(w, r) itself.
//
// There is no JWT here: the middleware that parses one is tested in
// internal/pkg/authmw, and repeating it would test the signing library. What is
// injected is the Identity that middleware produces — so the permission gates
// on each route are real.

// ─── Harness ─────────────────────────────────────────────────────────────────

// api is the mounted router plus the tenant whose token the requests carry.
type api struct {
	router chi.Router
	tenant uuid.UUID
	user   uuid.UUID
	pool   *pgxpool.Pool
}

func newAPI(t *testing.T) *api {
	t.Helper()
	pool := testinfra.Postgres(t)
	logger := zerolog.New(io.Discard)

	var tenant uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		"Banque HTTP", "http-"+uuid.NewString()[:8]).Scan(&tenant)
	if err != nil {
		t.Fatalf("create a tenant: %v", err)
	}

	// The caller is a real identity row, because three of the four policy
	// tables carry created_by REFERENCES identities(id) and a made-up UUID is
	// refused by the foreign key. risk_profiles is the exception — migration
	// 000039 declares created_by as a bare UUID — so a risk profile can record
	// an author who does not exist where the other three cannot. Noted here
	// rather than worked around silently.
	var user uuid.UUID
	err = pool.QueryRow(context.Background(), `
		INSERT INTO identities (tenant_id, username, email, display_name)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		tenant, "ciso-"+uuid.NewString()[:8], "ciso@example.test", "CISO").Scan(&user)
	if err != nil {
		t.Fatalf("create the calling identity: %v", err)
	}

	r := chi.NewRouter()
	NewTenantHandler(service.NewTenantService(repository.NewTenantRepository(pool), logger)).
		RegisterRoutes(r)
	NewRiskProfileHandler(service.NewRiskProfileService(repository.NewRiskProfileRepository(pool), logger)).
		RegisterRoutes(r)
	NewBehaviourPolicyHandler(service.NewBehaviourPolicyService(repository.NewBehaviourPolicyRepository(pool), logger)).
		RegisterRoutes(r)
	NewAttackPolicyHandler(service.NewAttackPolicyService(repository.NewAttackPolicyRepository(pool), logger)).
		RegisterRoutes(r)
	NewRemediationPolicyHandler(service.NewRemediationPolicyService(repository.NewRemediationPolicyRepository(pool), logger)).
		RegisterRoutes(r)

	return &api{router: r, tenant: tenant, user: user, pool: pool}
}

// caller is the identity a request is made under. Zero value: an ordinary user
// of a.tenant with no permissions at all, which is what a route with a gate
// must refuse.
type caller struct {
	tenant      *uuid.UUID
	superAdmin  bool
	permissions []string
}

func (a *api) do(t *testing.T, c caller, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal the request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	tenant := a.tenant
	if c.tenant != nil {
		tenant = *c.tenant
	}
	req = req.WithContext(authctx.With(req.Context(), authctx.Identity{
		TenantID:     tenant,
		UserID:       a.user,
		Permissions:  c.permissions,
		IsSuperAdmin: c.superAdmin,
	}))

	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

// envelope is the response shape every route answers in.
type envelope struct {
	Data json.RawMessage `json:"data"`
	Meta *struct {
		Page     int    `json:"page"`
		Limit    int    `json:"limit"`
		Total    int64  `json:"total"`
		TenantID string `json:"tenant_id"`
	} `json:"meta"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("the response is not an envelope: %v\n%s", err, rec.Body.String())
	}
	return e
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) envelope {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s answered %d, want %d\n%s", what, rec.Code, want, rec.Body.String())
	}
	if rec.Code == http.StatusNoContent {
		return envelope{}
	}
	return decode(t, rec)
}

var (
	superAdmin = caller{superAdmin: true, permissions: []string{
		"risk:read", "risk:write", "ueba:read", "ueba:write",
		"attack_paths:read", "attack_paths:write",
		"vulnerabilities:read", "vulnerabilities:write",
	}}
	riskReader = caller{permissions: []string{"risk:read"}}
	noRights   = caller{}
)

// ─── Tenant routes ───────────────────────────────────────────────────────────

// The route table itself: every path the handler registers answers, and a path
// it does not register 404s. A route silently absent is the failure mode a
// handler test that calls methods directly cannot see.
func TestTheTenantRoutesAreMountedWhereTheyAreDocumented(t *testing.T) {
	a := newAPI(t)

	created := wantStatus(t, a.do(t, superAdmin, http.MethodPost, "/tenants", map[string]any{
		"name": "Nouvelle banque", "slug": "mounted" + uuid.NewString()[:6], "plan": "standard",
	}), http.StatusCreated, "POST /tenants")

	var made struct{ ID uuid.UUID }
	if err := json.Unmarshal(created.Data, &made); err != nil {
		t.Fatalf("the created tenant is not readable: %v", err)
	}

	id := made.ID.String()
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodGet, "/tenants", nil, http.StatusOK},
		{http.MethodGet, "/tenants/" + id, nil, http.StatusOK},
		{http.MethodPut, "/tenants/" + id, map[string]any{"name": "Renommée"}, http.StatusOK},
		{http.MethodGet, "/tenants/" + id + "/stats", nil, http.StatusOK},
		{http.MethodDelete, "/tenants/" + id, nil, http.StatusNoContent},
		{http.MethodGet, "/tenants/" + id + "/inconnu", nil, http.StatusNotFound},
	} {
		rec := a.do(t, superAdmin, c.method, c.path, c.body)
		if rec.Code != c.want {
			t.Errorf("%s %s answered %d, want %d\n%s",
				c.method, c.path, rec.Code, c.want, rec.Body.String())
		}
	}
}

// Creating a tenant is a super admin's act, and the handler refuses before the
// service is reached. A 403 rather than a 500 or a silent success.
func TestCreateIsRefusedToANonSuperAdmin(t *testing.T) {
	a := newAPI(t)
	slug := "refuse" + uuid.NewString()[:6]

	rec := a.do(t, noRights, http.MethodPost, "/tenants", map[string]any{
		"name": "Tentative", "slug": slug, "plan": "standard",
	})
	wantStatus(t, rec, http.StatusForbidden, "POST /tenants as an ordinary user")

	// And nothing was written: a 403 that still created the row would be worse
	// than no check at all.
	var n int
	if err := a.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tenants WHERE slug = $1`, slug).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the refused creation wrote a row anyway")
	}
}

// Each malformed input gets the status that says whose mistake it was: a
// body that is not JSON, a body that is JSON but fails validation, and an id
// that is not a UUID are three different answers.
func TestMalformedInputIsAnsweredPrecisely(t *testing.T) {
	a := newAPI(t)

	rec := a.do(t, superAdmin, http.MethodPost, "/tenants", "{ this is not json")
	e := wantStatus(t, rec, http.StatusBadRequest, "POST /tenants with broken JSON")
	if e.Error == nil || e.Error.Code != "INVALID_JSON" {
		t.Errorf("the error code is %v, want INVALID_JSON", e.Error)
	}

	// Valid JSON, invalid tenant: the plan is not one of the three.
	rec = a.do(t, superAdmin, http.MethodPost, "/tenants", map[string]any{
		"name": "Banque", "slug": "validate" + uuid.NewString()[:6], "plan": "gratuit",
	})
	wantStatus(t, rec, http.StatusUnprocessableEntity, "POST /tenants with an unknown plan")

	// A slug of one character fails min=2.
	rec = a.do(t, superAdmin, http.MethodPost, "/tenants", map[string]any{
		"name": "Banque", "slug": "x", "plan": "standard",
	})
	wantStatus(t, rec, http.StatusUnprocessableEntity, "POST /tenants with a one-character slug")

	for _, path := range []string{"/tenants/pas-un-uuid", "/tenants/pas-un-uuid"} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			var body any
			if method == http.MethodPut {
				body = map[string]any{"name": "Renommée"}
			}
			rec := a.do(t, superAdmin, method, path, body)
			e := wantStatus(t, rec, http.StatusBadRequest, method+" "+path)
			if e.Error == nil || e.Error.Code != "INVALID_ID" {
				t.Errorf("%s %s gave error %v, want INVALID_ID", method, path, e.Error)
			}
		}
	}
}

// A domain refusal reaches the client as the status the domain meant, not as a
// 500. This is the mapping httperr exists for, checked here on the three kinds
// the tenant routes can produce.
func TestDomainRefusalsKeepTheirStatus(t *testing.T) {
	a := newAPI(t)

	// Conflict: the slug is taken.
	slug := "conflit" + uuid.NewString()[:6]
	wantStatus(t, a.do(t, superAdmin, http.MethodPost, "/tenants", map[string]any{
		"name": "Première", "slug": slug, "plan": "standard",
	}), http.StatusCreated, "the first creation")
	wantStatus(t, a.do(t, superAdmin, http.MethodPost, "/tenants", map[string]any{
		"name": "Seconde", "slug": slug, "plan": "standard",
	}), http.StatusConflict, "a second tenant on the same slug")

	// Not found: an id that parses but names nothing.
	wantStatus(t, a.do(t, superAdmin, http.MethodGet, "/tenants/"+uuid.NewString(), nil),
		http.StatusNotFound, "GET of an unknown tenant")

	// Forbidden: a tenant admin reading someone else.
	other := wantStatus(t, a.do(t, superAdmin, http.MethodPost, "/tenants", map[string]any{
		"name": "Voisine", "slug": "voisine" + uuid.NewString()[:6], "plan": "standard",
	}), http.StatusCreated, "creating the other tenant")
	var neighbour struct{ ID uuid.UUID }
	if err := json.Unmarshal(other.Data, &neighbour); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, a.do(t, noRights, http.MethodGet, "/tenants/"+neighbour.ID.String(), nil),
		http.StatusForbidden, "a tenant admin reading an unrelated tenant")
}

// The listing carries the paging it actually used, and the tenant it was read
// for. A client that paged on numbers it sent rather than on these would walk
// past the end of the set.
func TestTheListingReportsThePagingItUsed(t *testing.T) {
	a := newAPI(t)

	e := wantStatus(t, a.do(t, superAdmin, http.MethodGet, "/tenants?limit=2&page=1", nil),
		http.StatusOK, "GET /tenants?limit=2")
	if e.Meta == nil {
		t.Fatal("the listing carries no meta")
	}
	if e.Meta.Limit != 2 || e.Meta.Page != 1 {
		t.Errorf("meta says page %d limit %d, want 1 and 2", e.Meta.Page, e.Meta.Limit)
	}
	if e.Meta.TenantID != a.tenant.String() {
		t.Errorf("meta names tenant %s, want %s", e.Meta.TenantID, a.tenant)
	}

	// An unparseable or absurd page falls back to the default rather than
	// reaching PostgreSQL as a negative OFFSET.
	for _, q := range []string{"?page=abc", "?page=-4", "?limit=zero", "?limit=0"} {
		e := wantStatus(t, a.do(t, superAdmin, http.MethodGet, "/tenants"+q, nil),
			http.StatusOK, "GET /tenants"+q)
		if e.Meta == nil || e.Meta.Page < 1 || e.Meta.Limit < 1 {
			t.Errorf("GET /tenants%s reported page/limit %+v", q, e.Meta)
		}
	}
}

// ─── Policy routes ───────────────────────────────────────────────────────────

// Every policy route is gated, and the gate is on the right verb: a reader may
// read and may not write. Four families, eight assertions — written as a table
// because the families are deliberately identical and a gap in one of them is
// exactly what a hand-written test per family misses.
func TestEveryPolicyRouteIsGatedOnItsOwnPermission(t *testing.T) {
	a := newAPI(t)

	for _, f := range []struct {
		base, read, write string
	}{
		{"/risk-profiles", "risk:read", "risk:write"},
		{"/behaviour-policies", "ueba:read", "ueba:write"},
		{"/attack-policies", "attack_paths:read", "attack_paths:write"},
		{"/remediation-policies", "vulnerabilities:read", "vulnerabilities:write"},
	} {
		// No permission at all: every route refuses.
		for _, path := range []string{"/presets", "/active", "/history"} {
			rec := a.do(t, noRights, http.MethodGet, f.base+path, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("GET %s%s without %s answered %d, want 403",
					f.base, path, f.read, rec.Code)
			}
		}
		rec := a.do(t, noRights, http.MethodPut, f.base+"/active", map[string]any{})
		if rec.Code != http.StatusForbidden {
			t.Errorf("PUT %s/active without %s answered %d, want 403", f.base, f.write, rec.Code)
		}

		// The read permission opens the reads and not the write.
		reader := caller{permissions: []string{f.read}}
		for _, path := range []string{"/presets", "/active", "/history"} {
			rec := a.do(t, reader, http.MethodGet, f.base+path, nil)
			if rec.Code != http.StatusOK {
				t.Errorf("GET %s%s with %s answered %d, want 200\n%s",
					f.base, path, f.read, rec.Code, rec.Body.String())
			}
		}
		rec = a.do(t, reader, http.MethodPut, f.base+"/active", map[string]any{})
		if rec.Code != http.StatusForbidden {
			t.Errorf("PUT %s/active with only %s answered %d, want 403",
				f.base, f.read, rec.Code)
		}
	}
}

// The active profile is reported together with whether the tenant chose it, and
// the flag flips when it does. An interface that lost this would present the
// platform's defaults as the customer's decision.
func TestActiveSaysWhetherTheTenantChose(t *testing.T) {
	a := newAPI(t)

	e := wantStatus(t, a.do(t, riskReader, http.MethodGet, "/risk-profiles/active", nil),
		http.StatusOK, "GET /risk-profiles/active")
	var before struct {
		Profile struct {
			Code     string     `json:"code"`
			TenantID *uuid.UUID `json:"tenant_id"`
		} `json:"profile"`
		Chosen bool `json:"chosen"`
	}
	if err := json.Unmarshal(e.Data, &before); err != nil {
		t.Fatalf("decode the active profile: %v", err)
	}
	if before.Chosen {
		t.Error("a tenant that has set nothing is reported as having chosen")
	}
	if before.Profile.Code != "balanced" {
		t.Errorf("scored under %q, want balanced", before.Profile.Code)
	}

	wantStatus(t, a.do(t, superAdmin, http.MethodPut, "/risk-profiles/active", map[string]any{
		"name":    "Notre appétit",
		"weights": map[string]any{"vuln_critical": 3},
	}), http.StatusOK, "PUT /risk-profiles/active")

	e = wantStatus(t, a.do(t, riskReader, http.MethodGet, "/risk-profiles/active", nil),
		http.StatusOK, "GET /risk-profiles/active after the PUT")
	var after struct {
		Profile struct {
			TenantID *uuid.UUID `json:"tenant_id"`
			Weights  struct {
				VulnCritical float64 `json:"vuln_critical"`
			} `json:"weights"`
		} `json:"profile"`
		Chosen bool `json:"chosen"`
	}
	if err := json.Unmarshal(e.Data, &after); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !after.Chosen {
		t.Error("after a PUT the tenant is still reported as not having chosen")
	}
	if after.Profile.TenantID == nil || *after.Profile.TenantID != a.tenant {
		t.Errorf("the active profile belongs to %v, want %s", after.Profile.TenantID, a.tenant)
	}
	if after.Profile.Weights.VulnCritical != 3 {
		t.Errorf("vuln_critical is %v, want the 3 that was set", after.Profile.Weights.VulnCritical)
	}

	// And the history now has the version, with the caller recorded: who moved
	// a risk appetite is an audit question.
	e = wantStatus(t, a.do(t, riskReader, http.MethodGet, "/risk-profiles/history", nil),
		http.StatusOK, "GET /risk-profiles/history")
	var history []struct {
		Version   int        `json:"version"`
		CreatedBy *uuid.UUID `json:"created_by"`
	}
	if err := json.Unmarshal(e.Data, &history); err != nil {
		t.Fatalf("decode the history: %v", err)
	}
	if len(history) != 1 || history[0].Version != 1 {
		t.Fatalf("the history is %+v, want one version", history)
	}
	if history[0].CreatedBy == nil || *history[0].CreatedBy != a.user {
		t.Errorf("the version records %v as its author, want %s", history[0].CreatedBy, a.user)
	}
	if e.Meta == nil || e.Meta.Total != 1 {
		t.Errorf("the history meta says %+v, want a total of 1", e.Meta)
	}
}

// A policy the service refuses comes back as a 400 the client can act on, with
// the reason in words — not a 500 and not a constraint name.
func TestARefusedPolicyIsA400WithAReason(t *testing.T) {
	a := newAPI(t)

	for _, c := range []struct {
		what, path string
		body       map[string]any
	}{
		{
			"a risk threshold above its own ceiling", "/risk-profiles/active",
			map[string]any{"weights": map[string]any{"total_cap": 5, "high_risk_threshold": 8}},
		},
		{
			"deadlines that run backwards", "/remediation-policies/active",
			map[string]any{"deadlines": map[string]any{"critical_days": 200, "low_days": 5}},
		},
		{
			"a UEBA engine with every signal off", "/behaviour-policies/active",
			map[string]any{"signals": map[string]any{
				"off_hours":         map[string]any{"enabled": false},
				"new_country":       map[string]any{"enabled": false},
				"new_ip_prefix":     map[string]any{"enabled": false},
				"velocity":          map[string]any{"enabled": false},
				"brute_force":       map[string]any{"enabled": false},
				"priv_escalation":   map[string]any{"enabled": false},
				"lateral_movement":  map[string]any{"enabled": false},
				"data_exfiltration": map[string]any{"enabled": false},
			}},
		},
		{
			"an unknown preset", "/risk-profiles/active",
			map[string]any{"based_on": "ne_existe_pas"},
		},
	} {
		rec := a.do(t, superAdmin, http.MethodPut, c.path, c.body)
		e := wantStatus(t, rec, http.StatusBadRequest, c.what)
		if e.Error == nil || e.Error.Message == "" {
			t.Errorf("%s was refused without a message: %s", c.what, rec.Body.String())
		}
	}
}

// A body that is not JSON is a 400 on every policy route, and a body that is
// JSON but out of range is a 422. The two are different because one is a broken
// client and the other is a client asking for something the product refuses.
func TestPolicyRoutesSeparateBrokenJSONFromInvalidValues(t *testing.T) {
	a := newAPI(t)

	for _, base := range []string{
		"/risk-profiles", "/behaviour-policies", "/attack-policies", "/remediation-policies",
	} {
		rec := a.do(t, superAdmin, http.MethodPut, base+"/active", "{ nope")
		e := wantStatus(t, rec, http.StatusBadRequest, "PUT "+base+"/active with broken JSON")
		if e.Error == nil || e.Error.Code != "INVALID_JSON" {
			t.Errorf("PUT %s/active gave %v, want INVALID_JSON", base, e.Error)
		}
	}

	// The attack policy's "every step is free" refusal is not reachable over
	// HTTP: base_cost is bounded at 0.1 by the validator, so a zero is a 422
	// before the service sees it. The service-level refusal is the second line,
	// and it is tested where it lives, in internal/service.
	rec := a.do(t, superAdmin, http.MethodPut, "/attack-policies/active", map[string]any{
		"weights": map[string]any{"base_cost": 0},
	})
	wantStatus(t, rec, http.StatusUnprocessableEntity, "a base cost of zero")

	// Out of range: the weights are bounded at 10 by the validator.
	rec = a.do(t, superAdmin, http.MethodPut, "/risk-profiles/active", map[string]any{
		"weights": map[string]any{"vuln_critical": 99},
	})
	wantStatus(t, rec, http.StatusUnprocessableEntity, "a weight above its maximum")

	// And a severity outside the four the model allows.
	rec = a.do(t, superAdmin, http.MethodPut, "/behaviour-policies/active", map[string]any{
		"signals": map[string]any{"off_hours": map[string]any{"severity": "URGENT"}},
	})
	wantStatus(t, rec, http.StatusUnprocessableEntity, "a severity outside the four allowed")
}

// The presets listing carries its count, which is what a client pages on.
func TestPresetsCarryTheirCount(t *testing.T) {
	a := newAPI(t)

	e := wantStatus(t, a.do(t, riskReader, http.MethodGet, "/risk-profiles/presets", nil),
		http.StatusOK, "GET /risk-profiles/presets")
	var presets []struct {
		Code     string     `json:"code"`
		TenantID *uuid.UUID `json:"tenant_id"`
	}
	if err := json.Unmarshal(e.Data, &presets); err != nil {
		t.Fatalf("decode the presets: %v", err)
	}
	if e.Meta == nil || e.Meta.Total != int64(len(presets)) {
		t.Errorf("meta says %+v for %d presets", e.Meta, len(presets))
	}
	for _, p := range presets {
		if p.TenantID != nil {
			t.Errorf("preset %s is owned by tenant %s", p.Code, p.TenantID)
		}
	}
}

// The tenant a policy is written for comes from the token, never from the
// request. There is no path parameter to point elsewhere — this test holds that
// shape by writing under one identity and reading under another.
func TestAPolicyIsWrittenForTheTokensTenant(t *testing.T) {
	a := newAPI(t)

	var neighbour uuid.UUID
	err := a.pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		"Voisine", "voisine-"+uuid.NewString()[:8]).Scan(&neighbour)
	if err != nil {
		t.Fatal(err)
	}

	wantStatus(t, a.do(t, superAdmin, http.MethodPut, "/behaviour-policies/active", map[string]any{
		"thresholds": map[string]any{"velocity_threshold": 777},
	}), http.StatusOK, "PUT /behaviour-policies/active")

	// Read as the neighbour: it must still be on the standard thresholds.
	asNeighbour := caller{tenant: &neighbour, permissions: []string{"ueba:read"}}
	e := wantStatus(t, a.do(t, asNeighbour, http.MethodGet, "/behaviour-policies/active", nil),
		http.StatusOK, "GET /behaviour-policies/active as the neighbour")
	var got struct {
		Policy struct {
			Thresholds struct {
				VelocityThreshold int `json:"velocity_threshold"`
			} `json:"thresholds"`
		} `json:"policy"`
		Chosen bool `json:"chosen"`
	}
	if err := json.Unmarshal(e.Data, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Chosen {
		t.Error("the neighbour is reported as having chosen a policy it never set")
	}
	if got.Policy.Thresholds.VelocityThreshold == 777 {
		t.Error("one tenant's threshold is visible to another")
	}
}

// ─── The helpers ─────────────────────────────────────────────────────────────

// queryInt is what turns a query string into paging, and every one of these
// cases arrives from a real client sooner or later.
func TestQueryInt(t *testing.T) {
	for _, c := range []struct {
		in   string
		def  int
		want int
	}{
		{"", 50, 50},
		{"10", 50, 10},
		{"0", 50, 50},
		{"-3", 50, 50},
		{"abc", 50, 50},
		{"12abc", 50, 12}, // Sscanf stops at the first non-digit
		{"99999999999999999999", 50, 50},
	} {
		if got := queryInt(c.in, c.def); got != c.want {
			t.Errorf("queryInt(%q, %d) = %d, want %d", c.in, c.def, got, c.want)
		}
	}
}
