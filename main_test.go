package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── A fake OpenBao ──────────────────────────────────────────────────────────
//
// Not a mock of this package's own types: a real HTTP server speaking the kv v2
// shapes, so the tests exercise the URL rewriting, the token header, the
// response envelope and the error envelope rather than asserting that a stub was
// called. The three things that have actually gone wrong in this subsystem —
// data/metadata inserted at the wrong segment, `.data.data` unwrapped one level
// short, and 403 reported as a network problem — are all invisible to a mock and
// all caught here.

type fakeBao struct {
	srv *httptest.Server
	// path (logical, e.g. "kv/adx/app") -> payload
	secrets map[string]map[string]any
	version int
	// forbid holds logical paths that answer 403, the way OpenBao does for both
	// "no policy" and "does not exist".
	forbid map[string]bool
	reads  int64 // data reads served, for the cache assertions
	logins int64
}

func newFakeBao(t *testing.T) *fakeBao {
	t.Helper()
	f := &fakeBao{
		secrets: map[string]map[string]any{},
		forbid:  map[string]bool{},
		version: 1,
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.logins, 1)
		writeJSON(w, 200, map[string]any{
			"auth": map[string]any{"client_token": "s.faketoken"},
		})
	})

	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			baoError(w, 400, "missing client token")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 3 {
			baoError(w, 404, "no handler for route")
			return
		}
		mount, kind, sub := parts[0], parts[1], parts[2]
		logical := mount + "/" + sub

		if f.forbid[logical] {
			// ★ 403, exactly as OpenBao answers for a path that does not exist
			// AND for one the policy does not grant. The tool must not claim to
			// know which.
			baoError(w, 403, "1 error occurred:\n\t* permission denied\n\n")
			return
		}
		data, ok := f.secrets[logical]
		if !ok {
			baoError(w, 404, "")
			return
		}

		switch kind {
		case "data":
			atomic.AddInt64(&f.reads, 1)
			writeJSON(w, 200, map[string]any{
				"data": map[string]any{
					"data":     data,
					"metadata": map[string]any{"version": f.version},
				},
			})
		case "metadata":
			writeJSON(w, 200, map[string]any{
				"data": map[string]any{"current_version": f.version},
			})
		default:
			baoError(w, 404, "unknown kv segment")
		}
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func baoError(w http.ResponseWriter, code int, msg string) {
	errs := []string{}
	if msg != "" {
		errs = append(errs, msg)
	}
	writeJSON(w, code, map[string]any{"errors": errs})
}

// testClient wires a Client at the fake, with a cache in a temp dir and a token
// set so no AppRole files are needed.
func testClient(t *testing.T, f *fakeBao) *Client {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BAO_ADDR", f.srv.URL)
	t.Setenv("BAO_TOKEN", "s.faketoken")
	t.Setenv("BAOIST_CACHE", dir)
	return NewClient()
}

func mustParse(t *testing.T, s string) Ref {
	t.Helper()
	r, err := ParseRef(s)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", s, err)
	}
	return r
}

// ── Reference parsing ───────────────────────────────────────────────────────

func TestParseRef(t *testing.T) {
	cases := []struct {
		in   string
		path string
		sel  []string
	}{
		{"bao:kv/adx/app/db#PASSWORD", "kv/adx/app/db", []string{"PASSWORD"}},
		{"bao:kv/adx/s3/accounts/elephant#elephant.secret", "kv/adx/s3/accounts/elephant", []string{"elephant", "secret"}},
		// Surrounding slashes are noise, not meaning: a policy line and a copied
		// UI path disagree about them and both must resolve the same.
		{"bao:/kv/adx/app/db/#PASSWORD", "kv/adx/app/db", []string{"PASSWORD"}},
		{"bao:kv/x#a.b.c", "kv/x", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := mustParse(t, c.in)
		if got.Path != c.path {
			t.Errorf("%s: path = %q, want %q", c.in, got.Path, c.path)
		}
		if strings.Join(got.Selector, ".") != strings.Join(c.sel, ".") {
			t.Errorf("%s: selector = %v, want %v", c.in, got.Selector, c.sel)
		}
	}
}

// Every malformed reference must be exit 2 — a USAGE error the caller should
// never retry. Getting one of these classified as 4 would make a supervisor
// retry a typo forever, which is precisely what the exit codes exist to prevent.
func TestParseRef_MalformedIsUsageError(t *testing.T) {
	for _, in := range []string{
		"kv/adx/app#PASSWORD", // no bao: prefix
		"bao:kv/adx/app",      // no '#'
		"bao:#PASSWORD",       // empty path
		"bao:kv/adx/app#",     // empty selector
		"bao:/#x",             // path is only slashes
	} {
		_, err := ParseRef(in)
		if err == nil {
			t.Fatalf("ParseRef(%q) accepted a malformed reference", in)
		}
		if code := exitCodeFor(err); code != 2 {
			t.Errorf("ParseRef(%q): exit code %d, want 2 (%v)", in, code, err)
		}
	}
}

// ── kv v2 path rewriting ────────────────────────────────────────────────────
//
// The `data`/`metadata` segment goes after the MOUNT, not at the front and not
// at the end. Every way of getting it wrong presents as a permissions mystery,
// which is why it lives in one function and is pinned here.

func TestKvV2Rewrite(t *testing.T) {
	r := mustParse(t, "bao:kv/adx/elephant/nodes/imaging#POSTGRES_PASSWORD")
	if got, want := r.dataURL("https://b"), "https://b/v1/kv/data/adx/elephant/nodes/imaging"; got != want {
		t.Errorf("dataURL = %q, want %q", got, want)
	}
	if got, want := r.metaURL("https://b"), "https://b/v1/kv/metadata/adx/elephant/nodes/imaging"; got != want {
		t.Errorf("metaURL = %q, want %q", got, want)
	}
	// A path that is only a mount still has to be rewritten, not left bare.
	if got, want := insertSeg("kv", "data"), "kv/data"; got != want {
		t.Errorf("insertSeg(kv) = %q, want %q", got, want)
	}
}

// ── Selector walking ────────────────────────────────────────────────────────

func TestApply_FlatAndNestedUseTheSameSyntax(t *testing.T) {
	data := map[string]any{
		"POSTGRES_PASSWORD": "hunter2",
		"elephant":          map[string]any{"access": "AKIA", "secret": "shh"},
		"port":              float64(5432),
		"tls":               true,
	}
	for _, c := range []struct{ sel, want string }{
		{"POSTGRES_PASSWORD", "hunter2"},
		{"elephant.secret", "shh"},
		{"port", "5432"},
		{"tls", "true"},
	} {
		got, err := mustParse(t, "bao:kv/x#"+c.sel).apply(data)
		if err != nil {
			t.Fatalf("#%s: %v", c.sel, err)
		}
		if got != c.want {
			t.Errorf("#%s = %q, want %q", c.sel, got, c.want)
		}
	}
}

// ★ An object must never stringify. `map[access:AKIA secret:shh]` handed to S3
// as a credential fails as a 403 inside a pipeline run, hours later and nowhere
// near the cause — the exact quiet-wrong-value failure this tool exists to stop.
func TestApply_ObjectIsAnErrorAndSuggestsTheDeeperSelector(t *testing.T) {
	data := map[string]any{"elephant": map[string]any{"access": "AKIA", "secret": "shh"}}
	_, err := mustParse(t, "bao:kv/x#elephant").apply(data)
	if err == nil {
		t.Fatal("an object selector was stringified instead of refused")
	}
	if code := exitCodeFor(err); code != 3 {
		t.Errorf("exit code %d, want 3 (configuration)", code)
	}
	msg := err.Error()
	for _, want := range []string{"OBJECT", "access", "secret", "#elephant.access"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message does not mention %q:\n%s", want, msg)
		}
	}
}

// A missing field must list what IS there. "no field X" alone sends the reader
// to the wrong place when the answer is a spelling difference.
func TestApply_MissingFieldListsWhatIsPresent(t *testing.T) {
	data := map[string]any{"ACCESS_KEY": "a", "SECRET_KEY": "b"}
	_, err := mustParse(t, "bao:kv/x#SECRET").apply(data)
	if err == nil {
		t.Fatal("a missing field resolved")
	}
	if !strings.Contains(err.Error(), "ACCESS_KEY") || !strings.Contains(err.Error(), "SECRET_KEY") {
		t.Errorf("error does not list the present fields:\n%s", err)
	}
}

func TestApply_DescendingIntoAScalarSaysSo(t *testing.T) {
	data := map[string]any{"PASSWORD": "hunter2"}
	_, err := mustParse(t, "bao:kv/x#PASSWORD.nope").apply(data)
	if err == nil {
		t.Fatal("descended into a string")
	}
	if code := exitCodeFor(err); code != 3 {
		t.Errorf("exit code %d, want 3", code)
	}
}

// ── Resolution against the fake ─────────────────────────────────────────────

func TestResolve_UnwrapsKvV2DataData(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/app/db"] = map[string]any{"PASSWORD": "hunter2"}
	c := testClient(t, f)

	got, err := c.Resolve(mustParse(t, "bao:kv/adx/app/db#PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

// ★★ THE PROPERTY THE TOOL EXISTS FOR.
//
// OpenBao does not auto-unseal. If reading a credential required a live Bao,
// every power event would deadlock the fleet until a human pasted an unseal key.
// A Bao Agent's own cache does NOT provide this — it caches tokens and leases,
// not KV responses, and returns nothing at all with the server down (measured).
//
// So: fetch once, take the server away entirely, and the value must still
// resolve. If this test ever starts failing, the reason for the tool is gone.
func TestResolve_ServesFromCacheWithBaoCompletelyGone(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/app/db"] = map[string]any{"PASSWORD": "hunter2"}
	c := testClient(t, f)
	ref := mustParse(t, "bao:kv/adx/app/db#PASSWORD")

	if _, err := c.Resolve(ref); err != nil {
		t.Fatal(err)
	}
	f.srv.Close() // Bao is now sealed, down, unreachable — pick one.

	got, err := c.Resolve(ref)
	if err != nil {
		t.Fatalf("a cached reference stopped resolving when Bao went away: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
	// A fresh process must behave the same — the cache is on disk, not in RAM.
	fresh := NewClient()
	if got, err := fresh.Resolve(ref); err != nil || got != "hunter2" {
		t.Errorf("a new process did not read the on-disk cache: %q %v", got, err)
	}
}

// A cache HIT must not contact Bao at all. This is what makes resolution cheap
// enough to do per-operation instead of pre-rendering a file — the whole reason
// the template approach could be dropped.
func TestResolve_CacheHitDoesNotContactBao(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/app/db"] = map[string]any{"A": "1", "B": "2"}
	c := testClient(t, f)

	for _, sel := range []string{"A", "B", "A"} {
		if _, err := c.Resolve(mustParse(t, "bao:kv/adx/app/db#"+sel)); err != nil {
			t.Fatal(err)
		}
	}
	// Cached per PATH, not per ref: three resolutions over one record is one read.
	if n := atomic.LoadInt64(&f.reads); n != 1 {
		t.Errorf("served %d data reads for 3 refs into one path, want 1", n)
	}
}

// An UNCACHED reference with Bao unreachable must fail loudly as `unavailable`
// (4), never as an empty string. An empty credential is the failure that reaches
// S3 as a 403 inside a job hours later.
func TestResolve_UncachedAndUnreachableIsExit4(t *testing.T) {
	f := newFakeBao(t)
	c := testClient(t, f)
	f.srv.Close()

	got, err := c.Resolve(mustParse(t, "bao:kv/adx/app/db#PASSWORD"))
	if err == nil {
		t.Fatalf("resolved %q with Bao unreachable and nothing cached", got)
	}
	if got != "" {
		t.Errorf("returned a value alongside an error: %q", got)
	}
	if code := exitCodeFor(err); code != 4 {
		t.Errorf("exit code %d, want 4 (unavailable — retrying may help)", code)
	}
	if !strings.Contains(err.Error(), "does not auto-unseal") {
		t.Errorf("the unavailable message does not mention the sealed case:\n%s", err)
	}
}

// ★ 403 is the message that wastes the most time, because OpenBao uses it for
// both "denied" and "does not exist". It must be exit 3 (do not retry) and must
// name both possibilities with the real kv/data and kv/metadata policy lines.
func TestResolve_ForbiddenNamesBothCausesAndIsExit3(t *testing.T) {
	f := newFakeBao(t)
	f.forbid["kv/adx/forbidden"] = true
	c := testClient(t, f)

	_, err := c.Resolve(mustParse(t, "bao:kv/adx/forbidden#X"))
	if err == nil {
		t.Fatal("a 403 resolved")
	}
	if code := exitCodeFor(err); code != 3 {
		t.Errorf("exit code %d, want 3 (configuration — retrying will not help)", code)
	}
	msg := err.Error()
	for _, want := range []string{
		"does not grant",
		"does not exist",
		`"kv/data/adx/forbidden"`,
		`"kv/metadata/adx/forbidden"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("403 message is missing %q:\n%s", want, msg)
		}
	}
	// The multierror envelope must be unwrapped, not dumped.
	if strings.Contains(msg, "1 error occurred") {
		t.Errorf("Bao's multierror scaffolding leaked into the message:\n%s", msg)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Errorf("Bao's own message was lost:\n%s", msg)
	}
}

func TestResolve_MissingPathIs404AndSaysItIsNotPermissions(t *testing.T) {
	f := newFakeBao(t)
	c := testClient(t, f)
	f.secrets["kv/adx/other"] = map[string]any{"X": "1"} // mount is live

	_, err := c.Resolve(mustParse(t, "bao:kv/adx/never-written#X"))
	if err == nil {
		t.Fatal("a 404 resolved")
	}
	if !strings.Contains(err.Error(), "not a permissions problem") {
		t.Errorf("404 message does not rule out permissions:\n%s", err)
	}
}

// ── The cache on disk ───────────────────────────────────────────────────────

// It holds secrets at rest. 0600, and one file per path so the `_`-flattened
// name cannot collide two paths into one entry.
func TestCache_FileIsPrivateAndPerPath(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/one"] = map[string]any{"X": "1"}
	f.secrets["kv/adx/two"] = map[string]any{"X": "2"}
	c := testClient(t, f)

	for _, p := range []string{"one", "two"} {
		if _, err := c.Resolve(mustParse(t, "bao:kv/adx/"+p+"#X")); err != nil {
			t.Fatal(err)
		}
	}

	files, err := filepath.Glob(filepath.Join(c.cache.dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("cached %d files for 2 paths: %v", len(files), files)
	}
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if mode := st.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s has mode %04o, want 0600 — it holds a secret at rest", p, mode)
		}
	}
	// No leftover temp files from the write-then-rename.
	tmps, _ := filepath.Glob(filepath.Join(c.cache.dir, "*.tmp"))
	if len(tmps) != 0 {
		t.Errorf("temp files left behind: %v", tmps)
	}
}

// ★ The token is never written to disk. The cache holds VALUES, which the
// deployment needs in order to run while Bao is unreachable; a cached token
// would be a credential outliving the process for no benefit.
func TestCache_NeverHoldsTheToken(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	c := testClient(t, f)
	if _, err := c.Resolve(mustParse(t, "bao:kv/adx/app#X")); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(c.cache.dir, "*"))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "faketoken") {
			t.Fatalf("%s contains the client token:\n%s", p, b)
		}
	}
}

func TestCache_RecordsTheVersionItCameFrom(t *testing.T) {
	f := newFakeBao(t)
	f.version = 7
	f.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	c := testClient(t, f)
	if _, err := c.Resolve(mustParse(t, "bao:kv/adx/app#X")); err != nil {
		t.Fatal(err)
	}
	e, ok := c.cache.get("kv/adx/app")
	if !ok {
		t.Fatal("nothing cached")
	}
	if e.Version != 7 {
		t.Errorf("cached version %d, want 7 — `watch` compares against this", e.Version)
	}
	if e.Fetched.IsZero() || time.Since(e.Fetched) > time.Minute {
		t.Errorf("implausible fetched time %v", e.Fetched)
	}
	if paths := c.cache.paths(); len(paths) != 1 || paths[0] != "kv/adx/app" {
		t.Errorf("cache.paths() = %v, want [kv/adx/app]", paths)
	}
}

// `watch` polls METADATA, which does not transfer the secret. The steady state —
// nothing rotated — must therefore cost no data reads at all.
func TestCurrentVersion_ReadsMetadataNotTheSecret(t *testing.T) {
	f := newFakeBao(t)
	f.version = 3
	f.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	c := testClient(t, f)

	v, err := c.currentVersion("kv/adx/app")
	if err != nil {
		t.Fatal(err)
	}
	if v != 3 {
		t.Errorf("currentVersion = %d, want 3", v)
	}
	if n := atomic.LoadInt64(&f.reads); n != 0 {
		t.Errorf("a version check transferred the secret (%d data reads)", n)
	}
}

// ── AppRole ─────────────────────────────────────────────────────────────────

func TestLogin_UsesAppRoleFilesWhenNoTokenIsSet(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	dir := t.TempDir()
	// Trailing newlines are what `echo > role_id` leaves behind, and a token
	// with a newline in it fails as a 400 that reads like a broken AppRole.
	if err := os.WriteFile(filepath.Join(dir, "role_id"), []byte("rid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret_id"), []byte("sid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAO_ADDR", f.srv.URL)
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("BAOIST_CACHE", t.TempDir())
	t.Setenv("BAO_ROLE_ID_FILE", filepath.Join(dir, "role_id"))
	t.Setenv("BAO_SECRET_ID_FILE", filepath.Join(dir, "secret_id"))

	c := NewClient()
	if _, err := c.Resolve(mustParse(t, "bao:kv/adx/app#X")); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&f.logins); n != 1 {
		t.Errorf("%d AppRole logins, want 1", n)
	}
}

// ★ A missing credential FILE is a configuration error (3), not an availability
// one (4) — even though it surfaces before any HTTP request happens. An earlier
// version reported it as "cannot reach OpenBao", which sent the reader to check
// the network when the actual problem was a file nobody had placed.
func TestLogin_MissingCredentialFileIsConfigNotUnavailable(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	t.Setenv("BAO_ADDR", f.srv.URL)
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("BAOIST_CACHE", t.TempDir())
	t.Setenv("BAO_ROLE_ID_FILE", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("BAO_SECRET_ID_FILE", filepath.Join(t.TempDir(), "absent"))

	c := NewClient()
	_, err := c.Resolve(mustParse(t, "bao:kv/adx/app#X"))
	if err == nil {
		t.Fatal("resolved with no credentials at all")
	}
	if code := exitCodeFor(err); code != 3 {
		t.Errorf("exit code %d, want 3 — a file nobody placed is not a network problem\n%v", code, err)
	}
	if !strings.Contains(err.Error(), "role_id") {
		t.Errorf("the error does not name the missing file:\n%s", err)
	}
}

// ── Error classification, as a table ────────────────────────────────────────
//
// The contract a supervisor depends on, in one place: 3 means stop, 4 means it
// might be worth retrying. Everything above asserts one row of this; this pins
// the mapping itself so a new error kind cannot quietly default to 1.

func TestExitCodes(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{classedError{code: 2, msg: "usage"}, 2},
		{configErr("wrong"), 3},
		{unavailableErr("down"), 4},
		{fmt.Errorf("something else"), 1},
		{fmt.Errorf("wrapped: %w", configErr("wrong")), 3},
	} {
		if got := exitCodeFor(c.err); got != c.want {
			t.Errorf("exitCodeFor(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// ── Token renewal ───────────────────────────────────────────────────────────
//
// ★ The bug these cover, in full: `login()` caches its token for the life of the
// process. `bm get` never met that — it is a fresh process every time — but
// `bm watch` runs for days against an AppRole whose token_ttl is 20 MINUTES. So
// the watcher worked for one TTL and then failed every poll forever, printing
// "keeping cached copy" on every path: the message that means "all is well, I am
// riding this out". A dead watcher was indistinguishable from a healthy one.
//
// Nothing caught it because every existing test used a client for one call.

// expiringBao accepts exactly one token and rejects every earlier one with 403,
// which is what an expired lease looks like from the client side.
type expiringBao struct {
	*fakeBao
	live    string // the only token currently accepted
	logins  int64
	rejects int64
}

func newExpiringBao(t *testing.T) *expiringBao {
	t.Helper()
	e := &expiringBao{fakeBao: &fakeBao{
		secrets: map[string]map[string]any{},
		forbid:  map[string]bool{},
		version: 1,
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&e.logins, 1)
		e.live = fmt.Sprintf("s.token-%d", n)
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": e.live}})
	})
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != e.live {
			atomic.AddInt64(&e.rejects, 1)
			baoError(w, 403, "permission denied")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 3 {
			baoError(w, 404, "")
			return
		}
		logical := parts[0] + "/" + parts[2]
		if e.forbid[logical] {
			baoError(w, 403, "permission denied")
			return
		}
		data, ok := e.secrets[logical]
		if !ok {
			baoError(w, 404, "")
			return
		}
		if parts[1] == "metadata" {
			writeJSON(w, 200, map[string]any{"data": map[string]any{"current_version": e.version}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"data": data, "metadata": map[string]any{"version": e.version}}})
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *expiringBao) expire() { e.live = "s.expired-and-gone" }

func expiringClient(t *testing.T, e *expiringBao) *Client {
	t.Helper()
	dir := t.TempDir()
	creds := t.TempDir()
	if err := os.WriteFile(filepath.Join(creds, "role_id"), []byte("rid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(creds, "secret_id"), []byte("sid"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAO_ADDR", e.srv.URL)
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("BAOIST_CACHE", dir)
	t.Setenv("BAO_ROLE_ID_FILE", filepath.Join(creds, "role_id"))
	t.Setenv("BAO_SECRET_ID_FILE", filepath.Join(creds, "secret_id"))
	return NewClient()
}

// ★★ The regression test. A long-lived client whose token expires must log in
// again and keep working — not fail every call for the rest of the process.
func TestExpiredTokenIsRenewedOnTheNextCall(t *testing.T) {
	e := newExpiringBao(t)
	e.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	c := expiringClient(t, e)

	if _, err := c.currentVersion("kv/adx/app"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if n := atomic.LoadInt64(&e.logins); n != 1 {
		t.Fatalf("%d logins for the first call, want 1", n)
	}

	e.expire()

	if _, err := c.currentVersion("kv/adx/app"); err != nil {
		t.Fatalf("after the token expired the client gave up instead of renewing: %v", err)
	}
	if n := atomic.LoadInt64(&e.logins); n != 2 {
		t.Errorf("%d logins after expiry, want 2 — the token was not renewed", n)
	}
}

// A 403 on a path the policy genuinely does not grant must still be reported,
// not retried forever. One renewal attempt, then the error.
func TestGenuineForbiddenStillFailsAfterOneRenewal(t *testing.T) {
	e := newExpiringBao(t)
	e.secrets["kv/adx/app"] = map[string]any{"X": "1"}
	c := expiringClient(t, e)
	if _, err := c.currentVersion("kv/adx/app"); err != nil {
		t.Fatal(err)
	}

	// A path the policy genuinely denies — denied no matter how fresh the token
	// is, which is what separates "expired" from "not granted".
	e.forbid["kv/adx/app"] = true
	before := atomic.LoadInt64(&e.logins)
	if _, err := c.currentVersion("kv/adx/app"); err == nil {
		t.Fatal("a permanent 403 resolved")
	}
	if got := atomic.LoadInt64(&e.logins) - before; got != 1 {
		t.Errorf("%d extra logins on a permanent 403, want exactly 1", got)
	}
}

// A caller-supplied BAO_TOKEN must NOT trigger a re-login: login() hands the same
// value straight back, so the retry is a guaranteed-identical second 403.
func TestStaticBaoTokenIsNotRetried(t *testing.T) {
	f := newFakeBao(t)
	f.forbid["kv/adx/nope"] = true
	c := testClient(t, f) // sets BAO_TOKEN
	before := atomic.LoadInt64(&f.logins)
	_, _ = c.Resolve(mustParse(t, "bao:kv/adx/nope#X"))
	if got := atomic.LoadInt64(&f.logins) - before; got != 0 {
		t.Errorf("%d logins with a static BAO_TOKEN, want 0", got)
	}
}

// ★ refreshAll reports COUNTS so a total failure is distinguishable from one bad
// path. Losing every path means the watcher is broken; losing one means a grant
// is. They read identically per-path, which is how a dead watcher hid.
func TestRefreshAllReportsTotalFailureSeparately(t *testing.T) {
	f := newFakeBao(t)
	f.secrets["kv/adx/one"] = map[string]any{"X": "1"}
	f.secrets["kv/adx/two"] = map[string]any{"X": "2"}
	c := testClient(t, f)
	for _, p := range []string{"one", "two"} {
		if _, err := c.Resolve(mustParse(t, "bao:kv/adx/"+p+"#X")); err != nil {
			t.Fatal(err)
		}
	}

	_, failed, total := c.refreshAll()
	if total != 2 || failed != 0 {
		t.Errorf("healthy: failed=%d total=%d, want 0/2", failed, total)
	}

	f.forbid["kv/adx/one"] = true
	if _, failed, total = c.refreshAll(); failed != 1 || total != 2 {
		t.Errorf("one bad path: failed=%d total=%d, want 1/2", failed, total)
	}

	f.srv.Close() // Bao gone entirely
	if _, failed, total = c.refreshAll(); failed != total || total == 0 {
		t.Errorf("all gone: failed=%d total=%d, want failed==total>0", failed, total)
	}
}
