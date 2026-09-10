// baoist-monk — resolve `bao:` references, with a local cache that survives a
// sealed OpenBao.
//
//	baoist-monk get 'bao:kv/adx/s3/prickly-pear/accounts/elephant#elephant.secret'
//	baoist-monk env POSTGRES_PASSWORD=bao:kv/adx/elephant/nodes/imaging#POSTGRES_PASSWORD ...
//	baoist-monk watch --interval 3m --on-change '/usr/local/bin/rotated.sh'
//
// ── Why this exists ─────────────────────────────────────────────────────────
//
// The usual approach renders every secret into a file ahead of time, with a Bao
// Agent template. That requires knowing every kv path BEFORE the process starts,
// which is wrong for any application whose credential set is DATA — rows in a
// database, entries in a config repo — rather than deployment configuration.
//
// Everything painful about the pre-rendered approach comes from the rendering,
// not from secrets:
//
//   - a template block per path, and env vars kept in sync with it
//   - a nested-vs-flat special case, and a range-vs-index decision under it
//   - a policy line per path
//   - one unreadable path stopping the WHOLE render, presenting as a dead agent
//   - two sides that had to agree, and a cross-check to catch it when they did not
//
// A reference that names its own path and field makes all of that not exist.
//
// ── ★ The one property that must not be lost ────────────────────────────────
//
// OpenBao does not auto-unseal. Once sealed it stays sealed until a human pastes
// the key. The rendered file tolerated that by persisting; this tolerates it by
// CACHING ON DISK. A provisioned deployment starts and keeps working on cached
// values while Bao is unreachable.
//
// Note this is NOT free from the Bao Agent: its cache is a token/lease cache,
// not a KV response cache, and it does not serve reads while the server is down
// (measured: HTTP 000). The cache has to live here.
//
// ── What is deliberately NOT here ───────────────────────────────────────────
//
// No dependencies. The Bao HTTP API needed is three endpoints, and a static
// binary with no module graph is easier to ship inside an image and to reason
// about when it holds credentials.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const refPrefix = "bao:"

// ── Reference ───────────────────────────────────────────────────────────────

// Ref is a parsed `bao:<path>#<selector>`.
//
// The selector is dot-separated and walks the decoded JSON of the secret's data.
// That is what removes the nested-vs-flat special case: a flat scope is
// `#FIELD`, and versitygw's `{"acct": {"secret": …}}` is `#acct.secret`. Same
// syntax, no branch.
type Ref struct {
	Path     string   // e.g. kv/adx/elephant/nodes/imaging
	Selector []string // e.g. ["POSTGRES_PASSWORD"] or ["elephant", "secret"]
}

func ParseRef(s string) (Ref, error) {
	if !strings.HasPrefix(s, refPrefix) {
		return Ref{}, fmt.Errorf("not a bao: reference: %q", s)
	}
	body := strings.TrimPrefix(s, refPrefix)
	hash := strings.Index(body, "#")
	if hash < 0 {
		return Ref{}, fmt.Errorf("reference %q has no '#': expected bao:<path>#<field>", s)
	}
	path := strings.Trim(body[:hash], "/")
	sel := body[hash+1:]
	if path == "" {
		return Ref{}, fmt.Errorf("reference %q has an empty path", s)
	}
	if sel == "" {
		return Ref{}, fmt.Errorf("reference %q has an empty selector after '#'", s)
	}
	return Ref{Path: path, Selector: strings.Split(sel, ".")}, nil
}

// dataURL and metaURL implement the kv v2 split. A caller writes the LOGICAL
// path (kv/adx/…) exactly as it appears in a policy's `kv/data/…` line minus the
// `data`, and this inserts the segment. Getting that rewrite wrong reads as a
// permissions mystery, so it is done in one place.
func (r Ref) dataURL(addr string) string { return addr + "/v1/" + insertSeg(r.Path, "data") }
func (r Ref) metaURL(addr string) string { return addr + "/v1/" + insertSeg(r.Path, "metadata") }

func insertSeg(path, seg string) string {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 1 {
		return parts[0] + "/" + seg
	}
	return parts[0] + "/" + seg + "/" + parts[1]
}

// apply walks the selector over a decoded secret payload.
func (r Ref) apply(data map[string]any) (string, error) {
	var cur any = data
	for i, k := range r.Selector {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("selector %q: %q is not an object",
				strings.Join(r.Selector, "."), strings.Join(r.Selector[:i], "."))
		}
		cur, ok = m[k]
		if !ok {
			return "", fmt.Errorf("selector %q: no field %q at %s (present: %s)",
				strings.Join(r.Selector, "."), k, r.Path, strings.Join(keysOf(m), ", "))
		}
	}
	switch v := cur.(type) {
	case string:
		return v, nil
	case float64:
		return fmt.Sprintf("%v", v), nil
	case bool:
		return fmt.Sprintf("%t", v), nil
	default:
		// ★ Never stringify an object. A credential that silently becomes
		// `map[...]` is the empty-credential failure wearing a different hat: it
		// would be handed to S3 and fail as a 403 inside a run, hours later.
		return "", fmt.Errorf("selector %q at %s resolves to a %T, not a scalar",
			strings.Join(r.Selector, "."), r.Path, cur)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── Cache ───────────────────────────────────────────────────────────────────

// entry is one kv path's payload plus the version it came from. Cached per PATH,
// not per ref, so N refs into one record cost one fetch and one poll.
type entry struct {
	Path    string         `json:"path"`
	Version int            `json:"version"`
	Data    map[string]any `json:"data"`
	Fetched time.Time      `json:"fetched"`
}

type Cache struct {
	dir string
	mu  sync.Mutex
}

func (c *Cache) file(path string) string {
	return filepath.Join(c.dir, strings.ReplaceAll(path, "/", "_")+".json")
}

func (c *Cache) get(path string) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := os.ReadFile(c.file(path))
	if err != nil {
		return entry{}, false
	}
	var e entry
	if json.Unmarshal(b, &e) != nil {
		return entry{}, false
	}
	return e, true
}

func (c *Cache) put(e entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	// Temp + rename so a reader never sees a half-written file, and 0600 because
	// this holds secrets at rest.
	tmp := c.file(e.Path) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.file(e.Path))
}

func (c *Cache) paths() []string {
	ents, err := os.ReadDir(c.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range ents {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		if e, ok := c.getFile(filepath.Join(c.dir, f.Name())); ok {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out
}

func (c *Cache) getFile(p string) (entry, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return entry{}, false
	}
	var e entry
	if json.Unmarshal(b, &e) != nil {
		return entry{}, false
	}
	return e, true
}

// ── Client ──────────────────────────────────────────────────────────────────

type Client struct {
	addr  string
	cache *Cache
	hc    *http.Client

	tokMu sync.Mutex
	token string
}

func NewClient() *Client {
	addr := env("BAO_ADDR", "https://openbao.internal.astradx.com")
	return &Client{
		addr:  strings.TrimRight(addr, "/"),
		cache: &Cache{dir: env("BAOIST_CACHE", "/var/cache/baoist-monk")},
		hc:    &http.Client{Timeout: 15 * time.Second},
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// login authenticates with the AppRole and caches the token for this process.
//
// ★ The token is never written to disk. The cache holds secret VALUES, which the
// deployment needs in order to run while Bao is unreachable; a token would be a
// credential that outlives the process for no benefit.
func (c *Client) login() (string, error) {
	c.tokMu.Lock()
	defer c.tokMu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	if t := os.Getenv("BAO_TOKEN"); t != "" {
		c.token = t
		return t, nil
	}
	roleFile := env("BAO_ROLE_ID_FILE", "/etc/bao/role_id")
	secFile := env("BAO_SECRET_ID_FILE", "/etc/bao/secret_id")
	rid, err := os.ReadFile(roleFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", roleFile, err)
	}
	sid, err := os.ReadFile(secFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", secFile, err)
	}
	body, _ := json.Marshal(map[string]string{
		"role_id":   strings.TrimSpace(string(rid)),
		"secret_id": strings.TrimSpace(string(sid)),
	})
	resp, err := c.hc.Post(c.addr+"/v1/auth/approle/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("approle login: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("approle login returned no token")
	}
	c.token = out.Auth.ClientToken
	return c.token, nil
}

func (c *Client) getJSON(url string) (map[string]any, int, error) {
	tok, err := c.login()
	if err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Vault-Token", tok)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, resp.StatusCode, err
	}
	return out, 200, nil
}

// fetch reads a path from Bao and caches it.
func (c *Client) fetch(r Ref) (entry, error) {
	raw, _, err := c.getJSON(r.dataURL(c.addr))
	if err != nil {
		return entry{}, fmt.Errorf("read %s: %w", r.Path, err)
	}
	d, _ := raw["data"].(map[string]any)
	inner, _ := d["data"].(map[string]any)
	if inner == nil {
		return entry{}, fmt.Errorf("read %s: no data in response", r.Path)
	}
	ver := 0
	if md, ok := d["metadata"].(map[string]any); ok {
		if v, ok := md["version"].(float64); ok {
			ver = int(v)
		}
	}
	e := entry{Path: r.Path, Version: ver, Data: inner, Fetched: time.Now().UTC()}
	if err := c.cache.put(e); err != nil {
		return e, fmt.Errorf("cache %s: %w", r.Path, err)
	}
	return e, nil
}

// Resolve returns the value for a ref, preferring the cache.
//
// ★ A cache hit does NOT contact Bao. That is what makes resolution cheap enough
// to do per-operation, and what makes a sealed Bao invisible to a running
// deployment. Freshness is the watcher's job, not the reader's.
func (c *Client) Resolve(r Ref) (string, error) {
	if e, ok := c.cache.get(r.Path); ok {
		return r.apply(e.Data)
	}
	e, err := c.fetch(r)
	if err != nil {
		return "", err
	}
	return r.apply(e.Data)
}

// currentVersion asks only for METADATA — cheap, and it does not transfer the
// secret. This is what the poll loop uses to decide whether anything changed.
func (c *Client) currentVersion(path string) (int, error) {
	raw, _, err := c.getJSON((Ref{Path: path}).metaURL(c.addr))
	if err != nil {
		return 0, err
	}
	d, _ := raw["data"].(map[string]any)
	if v, ok := d["current_version"].(float64); ok {
		return int(v), nil
	}
	return 0, fmt.Errorf("%s: no current_version in metadata", path)
}

// ── Commands ────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "get":
		err = cmdGet(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "list":
		err = cmdList()
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "baoist-monk: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `baoist-monk — resolve bao: references, cached locally

  get <ref>                 print one value
  env NAME=<ref> [NAME=…]   print KEY=VALUE lines, for `+"`eval`"+` or a file
  watch [--interval 3m] [--on-change CMD]
                            poll kv METADATA for version changes, refresh the
                            cache, run CMD when anything actually changed
  list                      cached paths, versions and ages (no values)

A ref is  bao:<kv path>#<selector>  where the selector is dot-separated:

  bao:kv/adx/elephant/nodes/imaging#POSTGRES_PASSWORD
  bao:kv/adx/s3/prickly-pear/accounts/elephant#elephant.secret

Environment:
  BAO_ADDR              default https://openbao.internal.astradx.com
  BAO_TOKEN             use this token instead of AppRole login
  BAO_ROLE_ID_FILE      default /etc/bao/role_id
  BAO_SECRET_ID_FILE    default /etc/bao/secret_id
  BAOIST_CACHE    default /var/cache/baoist-monk
`)
}

func cmdGet(args []string) error {
	if len(args) != 1 {
		return errors.New("get takes exactly one reference")
	}
	r, err := ParseRef(args[0])
	if err != nil {
		return err
	}
	v, err := NewClient().Resolve(r)
	if err != nil {
		return err
	}
	fmt.Println(v)
	return nil
}

// cmdEnv resolves several NAME=ref pairs and prints KEY=VALUE.
//
// ★ Values are printed, never exported into a command line. Callers do
// `eval "$(elephant-bao env …)"` or redirect to a 0600 file — the value never
// appears in `ps`.
func cmdEnv(args []string) error {
	if len(args) == 0 {
		return errors.New("env takes NAME=<ref> pairs")
	}
	c := NewClient()
	var failed []string
	for _, a := range args {
		eq := strings.Index(a, "=")
		if eq < 0 {
			return fmt.Errorf("expected NAME=<ref>, got %q", a)
		}
		name, refStr := a[:eq], a[eq+1:]
		// A plain literal passes through unchanged — the same rule EnvResolver
		// uses, so a value can be pinned without inventing a scheme for it.
		if !strings.HasPrefix(refStr, refPrefix) {
			fmt.Printf("%s=%s\n", name, refStr)
			continue
		}
		r, err := ParseRef(refStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "baoist-monk: "+err.Error())
			failed = append(failed, name)
			continue
		}
		v, err := c.Resolve(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "baoist-monk: %s: %v\n", name, err)
			failed = append(failed, name)
			continue
		}
		fmt.Printf("%s=%s\n", name, v)
	}
	if len(failed) > 0 {
		// ★ Non-zero, and the names are on stderr. An unresolvable credential
		// must never look like an empty one: that is the failure that reaches S3
		// as a 403 inside a pipeline run hours later.
		return fmt.Errorf("could not resolve: %s", strings.Join(failed, ", "))
	}
	return nil
}

func cmdList() error {
	c := NewClient()
	paths := c.cache.paths()
	if len(paths) == 0 {
		fmt.Println("(cache empty)")
		return nil
	}
	for _, p := range paths {
		e, _ := c.cache.get(p)
		fmt.Printf("%-52s v%-4d %d field(s)  age %s\n",
			p, e.Version, len(e.Data), time.Since(e.Fetched).Round(time.Second))
	}
	return nil
}

func cmdWatch(args []string) error {
	interval := 3 * time.Minute
	var onChange string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 >= len(args) {
				return errors.New("--interval needs a duration")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return fmt.Errorf("--interval: %w", err)
			}
			interval = d
			i++
		case "--on-change":
			if i+1 >= len(args) {
				return errors.New("--on-change needs a command")
			}
			onChange = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	c := NewClient()
	fmt.Printf("watching %d cached path(s) every %s\n", len(c.cache.paths()), interval)
	for {
		changed := c.refreshAll()
		if len(changed) > 0 {
			fmt.Printf("changed: %s\n", strings.Join(changed, ", "))
			if onChange != "" {
				// The trigger gets the changed paths, so it can act narrowly.
				cmd := exec.Command("/bin/sh", "-c", onChange)
				cmd.Env = append(os.Environ(), "BAOIST_CHANGED="+strings.Join(changed, ","))
				cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "baoist-monk: on-change failed: %v\n", err)
				}
			}
		}
		time.Sleep(interval)
	}
}

// refreshAll compares each cached path's version against Bao and re-fetches only
// what moved. Returns the paths whose data actually changed.
//
// ★ METADATA first, deliberately. A version check does not transfer the secret,
// so the steady state — nothing has rotated — costs one small request per path
// and never puts a credential on the wire.
//
// ★ A path that cannot be read is LOGGED AND SKIPPED, never evicted. This is the
// opposite of the template design, where one unreadable path stopped everything:
// here a sealed Bao, a revoked grant or a network blip leaves every other value
// serving from cache, and leaves the failing one serving its last known value
// too. Losing a credential because Bao was briefly unreachable would be strictly
// worse than serving a stale one.
func (c *Client) refreshAll() []string {
	var changed []string
	for _, p := range c.cache.paths() {
		cur, err := c.currentVersion(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "baoist-monk: %s: %v (keeping cached copy)\n", p, err)
			continue
		}
		old, _ := c.cache.get(p)
		if cur == old.Version {
			continue
		}
		if _, err := c.fetch(Ref{Path: p}); err != nil {
			fmt.Fprintf(os.Stderr, "baoist-monk: %s: %v (keeping cached copy)\n", p, err)
			continue
		}
		changed = append(changed, fmt.Sprintf("%s v%d->v%d", p, old.Version, cur))
	}
	return changed
}
