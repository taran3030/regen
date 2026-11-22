---
name: api-recon
description: Invoke this skill when collecting website API endpoints.
---

# API Recon (Frontend API Reconnaissance)

Under **authorized** conditions, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI trigger points** (tabs, modals, table actions, etc.).

---

## Boundaries and Prohibitions (Agent Must Read -- Violations Are Out of Scope)

This skill **only performs API / parameter surface reconnaissance**, not vulnerability exploitation or penetration testing.

### Task Boundaries

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege escalation/brute force/fuzz vulnerabilities, packet tampering attacks, destructive operations |
| **Authentication** | Hook + stub/mock to bypass **client-side** login gates | Requesting or guessing usernames/passwords; attempting real login form submissions |
| **Runtime** | Hook APIs without credentials, use mock responses to let SPAs enter post-login shell | Flows that depend on real backend sessions to continue |

### Credential-Free Dynamic Analysis (Phase 3 Default)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** login, permission, and menu bootstrap APIs;
2. Return **structurally correct, success business code, optionally empty data** mock bodies for business query APIs;
3. Enable the frontend to render post-login pages in a no-backend or 401 environment, thereby triggering more XHR/fetch/WebSocket calls;
4. **Empty data, blank tables, and placeholder UI are expected** -- do not pivot to real login or vulnerability testing for this reason.

**In one sentence**: Use mocks to open up frontend routes and component mounting, **only record outbound requests**; what the backend returns doesn't matter -- what matters is **what additional APIs the frontend will send**.

### Hard Prohibitions

| Prohibited | Alternative |
|---|---|
| grep/curl/Read the main entry `index-*.js` to extract API paths before Phase 1 is complete | Run `OUTDIR/harvest_static.py` |
| Write `extract_apis.py` or similar scripts to replace harvest | Modify `OUTDIR/harvest_static.py` and re-run |
| Repeat the same grep/command after failing >=2 times | Change strategy: read tool_logs, modify harvest, check reference |
| Skip gates A/B and directly run original `scripts/` | Copy to OUTDIR and customize for target |
| Real username/password, OTP, OAuth authentication | stub/mock (see above) |
| Skip stub claiming "need real data", perform privilege escalation/injection tests | Only record outbound, within recon boundaries |
| Delete, export sensitive data, batch write, or other irreversible operations | Same applies to coverage clicks |
| Claim all pages and APIs have been obtained without completing runtime + dynamic enumeration | See "Completion Definition" or annotate limitations |
| Claim all parameters are known without completing parameter trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Infer required/optional from a single runtime sample | Multi-sample diff or validation rules/error inference |

---

## Two-Layer Model + Runtime Modes

| Layer | Output | Limitations |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, route drafts, packaging point field candidates | No HTTP methods; parameters need Phase 1b; misses runtime-concatenated URLs |
| **Runtime** (live session) | Methods + body + response + dynamic URLs + WS/SSE; multi-sample diff to complete parameters | Pages must actually render to send requests; single sample insufficient for required/optional |

| Runtime Mode | Engine | Use Case |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Click tabs/modals/tables for deeper feature point coverage |
| **both** | depth first, then coverage | Most complete, longest duration |

**Parameter methodology** (no universal script): paths use harvest/regex; parameters use **anchor-window expansion + UI binding chain + multi-sample diff + error inference** (grep recipes in [reference.md](reference.md) Section J).

---

## Completion Definition

All must be satisfied before claiming recon is complete:

- [ ] **Static**: Phase 1 harvest produced `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: At least depth or coverage completed; coverage/both requires **hooks active + dynamic enumeration loop**
- [ ] **Shell entry**: Business paths are accessed without redirecting to `/login` (note hash routing)
- [ ] **Parameters**: coverage/both completed parameter trigger matrix + `param_samples.json`; Phase 5 merged `params_merged.json`
- [ ] **Depth** (if module pages are blank): Phase 4 permission tree restoration and re-run, until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: Phase 5 outputs complete (see Phase 5 output table); `insert_assets` writes service and endpoint assets

---

## Scripts and Gates

`scripts/` are **reference templates only** -- **do not** run originals directly and treat results as final.

**Rule**: Read first -> customize for target -> write to `OUTDIR` (e.g. `recon/`) -> record in `CHANGES.md`; if template doesn't match, rewrite following the methodology, borrowing only the structure.

| Gate | When | Reference script -> OUTDIR copy | Common customizations |
|---|---|---|---|
| **A (Static)** | After Phase 0, **before first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | **Default regex works for most sites**; only modify endpoint regex, webpack/Vite `publicPath`, MPA exclude/cookie when manifest/dialect doesn't match |
| **B (Runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage key names, neutralize success values, stubs, login regex, api prefix, hash/history |

**SPA Mandatory Order** (non-swappable; Phase numbering takes priority over "explore first, script later"):

| Step | Required | Prohibited |
|---|---|---|
| After Phase 0 completes | Next Bash command = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (typically >500KB) |
| Gate A | Copy script -> customize as needed -> **run immediately** | Manually extract APIs first then decide whether to harvest |
| Before Phase 1 completes | `wc -l` to verify output; fix harvest and retry on 404 | Write custom extract scripts; repeatedly grep undownloaded URLs |
| From Phase 1b onward | grep only `OUTDIR/js/*.js` | Use main bundle instead of harvest |

- OK: Copy `harvest_static.py` -> (optional) modify regex -> **run immediately**
- NOT OK: curl main bundle -> grep multiple times -> write temp extract -> finally harvest
- **MPA**: After Phase 0, next Bash command = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and Output Constraints

| Constraint | Description |
|---|---|
| Large files | >100KB `index-*.js` **must not** be Read/grepped into context; use OUTDIR scripts for batch processing |
| grep output | Must use `\| head -20` or `-m 5`; conversation should only retain path summaries, do not paste bundle fragments |
| Verification | Use `wc -l`, `ls \| wc -l`; do not Read entire directories |
| regex probing | Optional, <=1 time, only on <=50KB small chunks or HTML; formal static uses harvest |
| reference | Recipes/templates/troubleshooting in [reference.md](reference.md), do not repeat inline in full |

---

## Execution Roadmap

```
Phase 0 Classification + OUTDIR
  -> Gate A -> Phase 1 harvest (* run immediately *)
  -> Phase 1b Parameter Reverse Engineering
  -> Phase 2 Authentication Three Gates -> config.json
  -> Gate B -> Phase 3 Runtime + Parameter Matrix
  -> Phase 4 Permission Tree (if needed) -> Re-run Phase 3
  -> Phase 5 Merge Report + insert_assets batch insert all discovered service and endpoint API assets; under no circumstances should discovered assets be omitted during insertion
```

Check off in order; **do not proceed to the next Phase before the previous one is complete**.

1. [ ] **Phase 0**: Initial probe SPA/MPA; create `OUTDIR` -> [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: Copy script -> **immediately** harvest -> `wc -l` verify -> [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: Anchor-window expansion + binding layer -> `param_candidates.json` -> [Phase 1b](#phase-1b--parameter-reverse-engineering)
4. [ ] **Phase 2**: Authentication three gates -> `config.json` -> [Phase 2](#phase-2--authentication-three-gates)
5. [ ] **Gate B**: Adjust runtime scripts -> [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm shell entry; parameter trigger matrix -> `param_samples.json`
7. [ ] **Phase 4** (if needed): Permission tree -> patch stubs -> re-run Phase 3 -> [Phase 4](#phase-4--permission-tree-restoration)
8. [ ] **Phase 5**: Merge outputs + report + `insert_assets` -> [Phase 5](#phase-5--merge-and-report)

---

## Phase 0 -- Classification

Fetch the entry HTML, **create `OUTDIR`** (do not modify files in the skill's `scripts/`):

- **SPA**: Empty shell + `<div id=app>` + chunks -> Phase 1-5
- **MPA**: SSR + `<form>`, no endpoint bundle -> After Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Output: `forms.txt`, `links.txt`, `api_inline.txt`. If SPA has forms ~ 0 -> switch to Phase 1.

---

## Phase 1 -- Static

Follow [Scripts and Gates](#scripts-and-gates) and [Tool and Output Constraints](#tool-and-output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: Parse HTML script -> webpack/Vite manifest -> download all lazy chunks -> output `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- chunk count vs manifest: 404s require harvest fix and retry, do not manually curl individual chunks
- `api_static.txt` too few -> loosen endpoint regex in OUTDIR and re-run (see reference)

### Phase 1b -- Parameter Reverse Engineering

Paths come from Phase 1; parameter fields require separate recon. grep rules in [Tool and Output Constraints](#tool-and-output-constraints).

**Completion criteria**: Important APIs can be answered -- field names, transport location, type inference, required/optional, sample values, confidence.

#### 1b.0 -- Transport Formats

| Format | Where parameters are | Static priority |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` near path anchor |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameters | `/user/:id` | Route table + `useParams` / `$route.params` |
| Encrypted/signed | Wrapped in `sign`/`data` | Hook encryption function inputs (reference Section D) |

Output: Annotate each API with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 -- Anchor-Window Expansion

Use known paths as anchors, expand the window to find packaging objects:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper Layer | Parameter Clues |
|---|---|
| axios instance | `data` / `params` |
| Unified request | Interceptor-injected global fields |
| OpenAPI client | Generated method signatures |
| React Query / SWR | Hook second argument |
| Vue composable | Composable input params |

Type remnants: `yup`/`zod`/rules, `Form.Item name=`, inline Swagger.

-> `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 -- Binding Layer

```
Form field -> onFinish/handleSubmit -> transform -> API payload
```

| Binding Source | Technique |
|---|---|
| Form submit | Follow submit -> transform -> API |
| Table search | `getFieldsValue()` -> `params` |
| Route | `:id` / `?tab=` |
| Interceptor | Global `tenantId`, pagination, sign |
| Enum select | `options` -> API enum values |

DevTools call stack: trace from `fetch`/`XHR.send` upward to find the packaging function.

#### 1b.3 -- Three Packaging Questions (not Phase 2 Auth Three Gates)

| Question | What to answer |
|---|---|
| **Assembly** | Where the payload is built, transform traces |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

The interceptor gate (Phase 2) also reveals globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 -- Bridging to Phase 3

Candidate fields come from static/binding layer; **required/optional/conditional dependencies** need Phase 3 parameter matrix + diff + Phase 5 error inference.

---

## Phase 2 -- Authentication Three Gates

grep in `OUTDIR/js/` (with `head`), write to `config.json` (recipes in reference):

| Gate | Question | Keywords |
|---|---|---|
| **Rendering Gate** | How does it determine logged-in status? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor Gate** | What triggers redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content Gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Do not treat localStorage key names as credentials -- must confirm from chunk/request chain.

**Exit = Gate B**: Conclusions go into `config.json`, and modify `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b -- API Observation (Optional)

Use OUTDIR's `preload.js` to confirm session key names, Authorization, nested API URLs:

| Config | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | Headers observation |
| `extractUrlsFromResponse: true` | Sub-APIs within responses |
| `observe.storageReads/cookieReads: true` | Backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

Coverage exports per round: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 -- Runtime

Must have passed Gate B; follow [Boundaries and Prohibitions](#boundaries-and-prohibitionsagent-must-read--violations-are-out-of-scope) and credential-free mock strategy.

`config.json` sets `"runtimeMode": "depth" | "coverage" | "both"` (templates in reference).

### Hooks and Stubs (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 Precise | auth/permission/bootstrap stubs | Pass first-screen authentication |
| L2 Negative Correction | All JSON responses | Unauthenticated code -> success |
| L3 Fallback | `/api` etc. not matched by L1 | Empty success body, open up UI |

- **depth**: fake auth + `forward` to modify business codes + `stubs`; traverse `routes` (hash/history); output `runtime_api.json`
- **coverage**: **document-start** inject `preload.js` (CDP `addScriptToEvaluateOnNewDocument` or Userscript)

Verification: `window.__API_RECON_PRELOAD__` exists; business paths do not redirect to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b -- Coverage Dynamic Enumeration (Required)

1. Main navigation/sidebar -- click each item, wait 1-3s for network
2. Tabs -- `role=tab`, `.ant-tabs-tab`
3. Tables -- first row view/edit/details
4. Toolbar -- export, filter, create new (**avoid irreversible deletions**)
5. Per module entry -- merge APIs/routes
6. SPA -- controlled `pushState` for uncovered paths in `routes.txt` (prohibited for MPA)

**Parameter trigger matrix** (required): Record once per operation type per module, **diff multiple samples**:

| Operation | Typically additional parameters |
|---|---|
| List first screen | Pagination + default filters |
| Click search | keyword, filter |
| Advanced filter | More optional fields |
| Create/edit | Complete entity |
| Batch/export/sort | `ids[]`, `exportType`, `sortField` |

**Outbound body/headers under stubs are still real** -- use requests as ground truth. Record -> `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: Phase 3a depth first, then 3b coverage

---

## Phase 4 -- Permission Tree Restoration

**Trigger**: Module pages blank / each route only has bootstrap (e.g. locale) -> content gate not passed.

| Symptom | Meaning |
|---|---|
| Shell entry successful | Rendering gate + interceptor gate passed |
| Sidebar items missing / clicking shows blank | Stub shape or permission codes incomplete |
| Same few APIs for every route | `v-if permission` not passing |
| `routes.txt` far fewer than bundle | Need to supplement from auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) -> `getResultTree` -> `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Stub checks: outer `response_code` consistent with interceptor gate; flat codes aligned with tree; `routes` cover all links in `route_map`.

After updating `config.json`, **re-run Phase 3**. For large SPAs, adjust `waitUntil`, `routeTimeout`, `perRouteMs` (see reference Sections A3/I).

---

## Phase 5 -- Merge and Report

### Output Table

| File | Phase | Content |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | Static bundle and paths |
| `param_candidates.json` | 1b | Static parameter field candidates |
| `config.json` | 2 | Three gates + runtime config |
| `runtime_api.json` | 3a | depth detailed recording (including WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | Multi-sample, click logs, details |
| `route_map.json` etc. | 4 | Permission tree intermediate files (if executed) |
| `params_merged.json` | 5 | Merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | Routes, APIs, params, feature points, limitations |
| **insert_assets** | 5 | Write all service and endpoint assets to asset library |

### 5b -- Parameter Merging

Diff from `param_samples.json`, **no universal merge script**. Confidence rules in reference Section J7 (high/medium/low/pending trigger).

### 5c -- Error Inference

Within authorized scope, send incomplete requests to read 400 responses (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Note `data` wrapping, `variables`, pre-encryption `bizData`.

Report must note: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, `CHANGES.md` summary relative to reference scripts.

`site_map.json` recommended structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

Additional fields and grep recipes in [reference.md](reference.md).

---

## General Notes

- **Framework-agnostic**: webpack/Vite/Angular lazy load methods are the same
- **Transport**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: Client-side fetch can be recorded; RSC/Server Actions are not fully enumerable
- **Blind spots**: JSVMP, WASM, HMAC/mTLS strong validation -> static + annotate limitations
- **Parameter blind spots**: Conditional dependencies, hidden params, WASM packaging -> "pending trigger" / "unreachable"
- **Static is the safety net**: When runtime is blocked, static can still enumerate endpoints

---

## Additional Resources

- Grep recipes, `config.json` templates, troubleshooting, hooks, parameter reverse engineering Section J, site_map templates: **[reference.md](reference.md)**
- Reference script paths in the [Scripts and Gates](#scripts-and-gates) table
