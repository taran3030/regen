# api-recon -- Reference Manual

Grep recipes, `config.json` templates, and troubleshooting. All grep commands target the `js/` directory. When bundles are single-line, you can first run `js-beautify` or `sed 's/}/}\n/g'`, but typically raw grep with context windows is sufficient.

## Script Descriptions

All files in `scripts/` are **reference templates** that must be customized for the target site before execution. Typical customization points:

| Script | Common Customizations |
|---|---|
| `harvest_static.py` | Endpoint regex, webpack/Vite manifest parsing, micro-frontend publicPath, retry/concurrency |
| `runtime_harvest.js` | Neutralize field names and success values, stub matching rules and body structure, routes source, WS recording, `waitUntil`/`routeTimeout`/`proxy` |
| `preload.js` | `loginPathRe`, L1 stubs, `neutralize.fields`, `apiPattern`, whether to enable L3, `recordDetail`, `observe.*`, `neutralizeVueRouter` |
| `spider_mpa.py` | `--exclude` destructive links, cookie, depth/max, same-domain filtering |
| `extract_route_map.py` | `routeMap` / `routeLink` regex, KEY naming patterns |
| `build_perm_tree.py` | `userRouteAuth` parsing, `ROOTS`/`PREFIX_PARENT` hierarchy heuristics, stub outer field names |
| `config.json` | Unified entry point for all site-specific parameters above |

Customized files should be placed in the task working directory (e.g. `recon/`), with specific changes relative to reference scripts noted in the report.

---

## A. Reverse Engineering the Three Gates

### A1. Rendering Gate -- "How does it determine logged-in status?"

```bash
grep -rhoaE '.{0,40}(isLogin|isAuthenticated|loggedIn|hasLogin|requireAuth)\b.{0,80}' js | head
grep -rhoaE 'function (getUser|getToken|getAuth)[0-9]?\([^)]*\)\{.{0,200}' js | head
grep -rhoaE '(localStorage|sessionStorage)\.getItem\("[^"]+"\)' js | sort -u
grep -rhoaE '(Cookies?|cookie)\.(get|load)\("[^"]+"\)' js | sort -u
grep -rhoaE '\batob\(|JSON\.parse\(|jwt|decode' js | head
```

Trace the chain `isLogin = f(getUser())` -> `getUser = decode(storage.read(KEY))`, determining the **storage key**, **container** (Cookie vs localStorage), and **encoding**:

| Encoding | config forgery method |
|---|---|
| Plain string / `"1"` / token | `"value": "anything-truthy"` |
| `JSON.parse(x)` | `"value": "json:{\"id\":1,\"username\":\"admin\"}"` |
| `JSON.parse(atob(x))` | `"value": "b64json:{\"id\":1,\"username\":\"admin\"}"` |
| JWT | Unsigned/`alg:none` JWT, or sign with key found in bundle |
| Encrypted (SM2/AES/RSA) | Find hardcoded keys; rendering gate only needs decodable blob to forge; otherwise fall back to static |

-> Write to `cookies` / `localStorage`.

### A2. Interceptor Gate -- "What triggers redirect to /login?"

```bash
grep -rhoaE '.{0,60}(interceptors\.response|axios|request\.use).{0,120}' js | head
grep -rhoaE '.{0,40}(response_code|errcode|errno|\bcode\b|\bret\b|\bstatus\b)\s*[=!]==?\s*[\-0-9]{1,4}.{0,60}' js | head -20
grep -rhoaE '.{0,40}(not logged in|please re-login|login expired|unauthorized|login invalid|authorization|token.{0,10}invalid).{0,40}' js | head
grep -rhoaE '.{0,30}(location\.href|router\.(push|replace)|navigate)\([^)]*login[^)]*\)' js | head
```

Determine: **field name**, **success value** (typically `0` or `200`), **failure value that triggers redirect**. Verify with a junk session:

```bash
curl -sk -X POST -H 'Cookie: <fakekey>=junk' https://target/api/<protected> -d '{}' -H 'Content-Type: application/json'
```

-> Write to `neutralize.fields` + `neutralize.success`.

### A3. Content Gate -- "Where do menus/permissions come from?"

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl|resource|nav)[^"]*"' js | sort -u
grep -rhoaE '.{0,30}(menus|permissions|menuList|routeList|authList|role_permissions)\b.{0,120}' js | head
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|hasPermission|checkAuth' js | head
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head
```

**Two data layers** (common in enterprise admin panels):

| API | Typical payload | Consumer |
|---|---|---|
| `.../role_permissions` | `{ permissions: string[], role_type }` | Route guards, button-level ACL |
| `.../permissions/all` | `tree[{ code, position, children }]` | Sidebar menu rendering |
| Bundle `userRouteAuth` | `{ CODE: { url, name? } }` | code -> frontend path |
| Bundle `routeMap` | `{ KEY: { name, link } }` | Alias resolution (webpack `o.DASHBOARD`) |

Read consumer code to confirm: how `getResultTree(tree, permissions)` filters, which field `v-if` / `hasAuth(code)` checks.

**Manual forge** (small sites): Build permissive payload -> `stubs`.

**Full permission tree restoration** (large sites, sidebar/submodules still blank): See **Section I**.

---

## B. config.json Template

```json
{
  "baseUrl": "https://target/",
  "runtimeMode": "both",
  "chromium": "/usr/bin/chromium",

  "cookies": [
    { "name": "auth", "value": "b64json:{\"id\":1,\"username\":\"admin\",\"role\":\"admin\",\"func\":{},\"permissions\":[\"*\"]}" }
  ],
  "localStorage": { "token": "faketoken", "isLogin": "1" },

  "neutralize": {
    "fields": ["response_code", "code", "errno", "ret", "status"],
    "success": 0,
    "flags": { "success": true, "message": "ok" }
  },
  "forward": true,
  "loginUrlPattern": "/login",
  "apiPattern": "/api/|/rest/|/graphql",

  "mockTier": "L1+L2",
  "recordDetail": true,
  "observe": {
    "storageReads": false,
    "cookieReads": false,
    "xhrHeaders": true
  },
  "neutralizeVueRouter": true,
  "stubs": [
    {
      "match": "permissions/all|/menu|role_permissions",
      "body": {
        "response_code": 0, "code": 0,
        "data": {
          "permissions": ["*"],
          "menus": [
            { "name": "dashboard", "path": "/dashboard", "show": true, "children": [] },
            { "name": "alert", "path": "/alert", "show": true, "children": [] }
          ]
        }
      }
    }
  ],

  "explore": {
    "clickTabs": true,
    "clickTables": true,
    "pushStateFallback": true,
    "maxMenuItems": 50
  },

  "routes": ["/dashboard", "/alert", "/asset", "/device", "/report", "/config", "/system"],
  "waitMs": 1500, "perRouteMs": 900, "headless": true,
  "waitUntil": "domcontentloaded",
  "routeTimeout": 12000,
  "proxy": "",

  "captureResponses": true, "recordWs": true, "respMax": 600
}
```

Field descriptions:
- `runtimeMode`: `depth` (Puppeteer), `coverage` (browser MCP), `both`
- `cookies[].value` prefix: `b64json:` -> base64(JSON); `json:` -> raw JSON; no prefix -> literal
- `forward: true` forwards real requests and rewrites code fields; `false` for fully offline stubs
- `mockTier`: coverage mode preload enabled layers, e.g. `L1+L2`, `L1+L2+L3`
- `routes` from `routes.txt`; after forging menus, harness automatically appends `<a href>`
- `captureResponses` / `recordWs` only effective in depth mode
- `waitUntil`: use `domcontentloaded` for large SPAs, avoid `networkidle2` which may hang
- `routeTimeout`: per-route `page.goto` timeout (milliseconds)
- `proxy`: Puppeteer `--proxy-server`; can also set `HTTP_PROXY` / `HTTPS_PROXY`

### B1. Dual Stub Template (role_permissions + permissions/all)

```json
"stubs": [
  {
    "match": "role_permissions",
    "body": {
      "response_code": 0,
      "data": {
        "permissions": ["MONITOR", "MONITOR_ALERT", "THREAT", "ASSETS_RISK"],
        "role_type": "SUPER_ADMIN"
      }
    }
  },
  {
    "match": "permissions/all",
    "body": {
      "response_code": 0,
      "data": [
        {
          "code": "MONITOR",
          "position": 1,
          "children": [
            { "code": "MONITOR_ALERT", "position": 1, "children": [] }
          ]
        }
      ]
    }
  }
]
```

Outer field names (`response_code` / `code` / `data`) must match the A2 interceptor gate; `permissions` must cover all leaf codes in the tree.

---

## C. Coverage Mode: Preload Configuration

Edit the `CONFIG` object at the top of `scripts/preload.js`, or replace before CDP injection:

```javascript
const CONFIG = {
  loginPathRe: /\/(login|signin)(\/|$|\?)/i,
  mockTier: 'L1+L2',
  forward: true,
  recordDetail: true,
  extractUrlsFromResponse: true,
  neutralizeVueRouter: true,
  observe: { storageReads: false, cookieReads: false, xhrHeaders: true },
  neutralize: { fields: ['response_code', 'code'], success: 0 },
  stubs: [ /* same as config.json stubs */ ],
  apiPattern: /\/(api|apis|v\d+|dev|internal|graphql)\//i,
};
```

Verification: `window.__API_RECON_PRELOAD__ === true` and pathname is stable.

Export recorded results:

```javascript
JSON.stringify({
  apis: [...window.__API_RECON_LOG__],
  detail: window.__API_RECON_DETAIL__,
  routes: [...(window.__API_RECON_ROUTES__ || [])],
  observe: window.__API_RECON_OBSERVE__,
}, null, 2)
```

---

## D. Preload / Runtime Hook Capabilities

Browser hook capabilities built into preload (coverage) and runtime_harvest (depth), and their coverage:

| Hook Capability | Value for API Discovery | Coverage |
|---|---|---|
| Hook fetch / XHR.open | Record request URL/method | OK: `recordDetail` + `__API_RECON_LOG__` |
| Hook XHR.setRequestHeader | Discover Authorization and other headers | OK: `observe.xhrHeaders` |
| Hook localStorage/cookie reads | Confirm session key names | Optional: `observe.storageReads/cookieReads` |
| Vue route extraction | Supplement frontendRoutes | OK: `__API_RECON_ROUTES__` (loaded routes) |
| Vue router guard neutralization / login redirect blocking | Open modules to trigger APIs | OK: `neutralizeVueRouter` + native redirect neutralization |
| React route extraction | Supplement routes | Limited: static + clicks; no dedicated hook |
| Page redirect blocking (login path) | Stay on page for analysis | Limited: only blocks login path, avoids blocking business navigation |
| Hook encryption libraries (CryptoJS/SM etc.) | Encrypted params -> plaintext API body | No: must manually hook encryption function inputs; write conclusions to config |
| Anti-debug bypass | Otherwise runtime cannot record APIs | No: must handle manually; static still usable |

---

## E. Endpoint Extraction Regex (When Static Results Are Too Few)

Loosen in `harvest_static.py`'s `extract_endpoints`, or manually:

```bash
grep -rhoaE '"/[a-z][A-Za-z0-9_/\-]{3,}"' js | sort -u
grep -rhoaE '/api/[a-zA-Z0-9_./-]+' js | sort -u
```

---

## F. Troubleshooting

| Symptom | Cause -> Resolution |
|---|---|
| Very few static APIs | Endpoint dialect mismatch -> loosen regex (Section D) |
| Chunk count << manifest | CSS-only or undeployed chunks; 404 already retried |
| Runtime still shows login page | Rendering gate error -> recheck A1: key name, container, encoding, domain |
| Shell entry successful but modules blank | Content gate -> forge menus (A3); `routes` paths may be wrong |
| Each route only has bootstrap/locale | Permission codes incomplete -> Section I permission tree restoration; check `role_permissions` + `permissions/all` dual stubs |
| Sidebar has items but sub-pages blank | Tree missing intermediate nodes or codes inconsistent with `userRouteAuth` |
| Every API redirects to login | Interceptor gate -> confirm `neutralize`; nested fields need extended walk logic |
| WS frames are 0 | Requires user interaction to subscribe; increase `perRouteMs` |
| Response bodies empty | Only `forward: true` has real responses |
| Chromium missing | Install chromium or set `config.chromium` / `CHROMIUM` |
| Mocks applied but still redirecting to login | Hook too late or missing `location.href` setter -> document-start + preload |
| Lists all empty | L3 empty arrays are normal; continue clicking tabs/settings/details |
| Mistakenly treating Redux actions as routes | Filter out internal paths containing get/set/change/clear/toggle/upload |
| Vue still redirecting to login | preload not at document-start -> change injection timing; or manually clear guards when `neutralizeVueRouter: false` |
| URLs in response but not in log | Enable `extractUrlsFromResponse`; or manually extract from `__API_RECON_DETAIL__` |
| Unknown Authorization header name | Enable `observe.xhrHeaders` or check request headers in DevTools |
| Runtime extremely slow / timing out | Change `waitUntil: domcontentloaded`; lower `routeTimeout`; do not use `networkidle2` |
| Proxy connection failed | Check `proxy` / environment variables; ensure Puppeteer and curl proxy ports match |

---

## G. Hardened Targets

When the server progressively validates sessions (unforgeable signed cookies, server-rendered menus that cannot be stubbed), runtime will stall at the shell. Expected behavior:

- **Static is sufficient for endpoint enumeration** -- module paths are in the code
- If authorization allows, run the same harness with a **real session**: `forward: true`, no neutralize needed, capture real methods/params/responses

---

## H. Single Task Checklist

1. Confirm authorization scope
2. **Read** `scripts/harvest_static.py` -> customize for target -> run -> review `api_static.txt`, `routes.txt`
3. **Phase 1b**: path anchor-window expansion + binding layer -> `param_candidates.json` (Section J)
4. Reverse engineer A1/A2/A3 -> write site-specific `config.json`
5. **Read and customize** `runtime_harvest.js` / `preload.js` before executing
6. `runtimeMode=depth`: `npm install` -> run customized harvest script
7. `runtimeMode=coverage/both`: document-start inject customized preload -> browser MCP dynamic enumeration + **parameter trigger matrix**
8. Modules not rendering -> **Section I permission tree restoration** -> patch stubs -> re-run
9. Parameter multi-sample diff + error inference -> `params_merged.json`
10. Merge -> `site_map.json` + `api_merged.txt`, honestly annotating coverage, gaps, and script customization points

---

## I. Permission Tree Restoration (Phase 4 Deep Dive)

Use when simple `menus: [{ path, show: true }]` forgery is ineffective and submodules still don't mount.

### I1. Locate Auth Module

```bash
grep -l 'userRouteAuth' js/*.js
grep -l 'routeMap\|routeLink' js/*.js
grep -rhoaE 'getResultTree|role_permissions|permissions/all' js | head
```

Record: **permission API path**, **response field names**, **consumer chunk filename**.

### I2. Extract routeMap

```bash
python3 scripts/extract_route_map.py recon/js recon/
# Output: recon/route_map.json
```

If `[!] no routeMap pattern found`: loosen regex in `extract_route_map.py`, or manually grep:

```bash
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head -20
```

### I3. Build Permission Tree + Stubs

```bash
python3 scripts/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Script logic:
1. Parse `userRouteAuth={MONITOR:{url:...},...}` (including webpack aliases `He=o.DASHBOARD`)
2. Use `route_map.json` to resolve alias -> real path
3. Infer parent by code prefix (`MONITOR_ALERT` -> `MONITOR`)
4. Output `permissions_tree.json`, `permissions_all_stub.json`, `role_permissions_stub.json`
5. With `--config`, automatically write to `config.json`'s `stubs` and extend `routes`

**Customize for target** (at script top):
- `DEFAULT_ROOTS`: Top-level module code list
- `DEFAULT_PREFIX_PARENT`: `PREFIX_` -> parent mapping
- `DEFAULT_EXTRA_PARENT`: Non-prefix orphan node relationships

### I4. Verify Stub Consistency

```bash
# permissions count should ~ equal userRouteAuth entry count
wc -l recon/perm_codes_all.txt
# routes should cover all links in route_map
python3 -c "import json; m=json.load(open('recon/route_map.json')); r=set(json.load(open('recon/config.json'))['routes']); print('missing', [v['link'] for v in m.values() if v['link'] not in r])"
```

### I5. Re-run Runtime and Compare

```bash
node recon/runtime_harvest.js recon/config.json
# Compare runtime_api.json entry count before and after forge; check if /attack, /asset etc. show module APIs
```

| Before forge | After forge (success) |
|---|---|
| Same 3-5 bootstrap APIs per route | Different routes trigger different module APIs |
| Only `/api/locale/language` | Module endpoints like `/api/web/...` appear |
| `routes.txt` single-digit routes | `routes` 80-110+ from route_map |

### I6. If Still Failing

- **Coverage mode**: Click sidebar + tabs, permission gating may only request after interaction
- **Stub fields**: Compare real API (curl + real session) nesting with stub
- **Additional guards**: grep `hasPermission|checkRole|func.` etc. button-level checks, extend `role_permissions.permissions`
- **Static fallback**: Module API paths still in `api_static.txt`, runtime only supplements METHOD/body; parameters retain `param_candidates.json` + recorded samples

---

## J. Parameter Reverse Engineering (Phase 1b / 5b / 5c)

**Methodology, not a universal script.** Find paths with regex; find parameters with anchor-window expansion + UI binding chain + multi-sample diff + error inference.

### J1. Anchor-Window Expansion -- From Path to Packaging Object

```bash
# Using Phase 1 known paths as anchors
grep -n '"/api/user/list"' js/*.js
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' js | head
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' js | head
grep -rhoaE '(get|post|put|delete|patch)\([^,]+,\s*\{' js | head
```

### J2. Wrapper Layers and Transport Formats

```bash
# axios / unified request
grep -rhoaE '(axios|request)\.(get|post|put|delete|patch)\(' js | head
grep -rhoaE 'interceptors\.(request|response)' js | head

# GraphQL
grep -rhoaE '(query|mutation)\s+\w+|gql`|graphql\(' js | head
grep -rhoaE '\$[a-zA-Z_]+\s*:\s*(Int|String|Boolean|\[)' js | head

# FormData / multipart
grep -rhoaE 'FormData|\.append\(' js | head

# Path parameters
grep -rhoaE 'path:\s*"/[^"]*:[^"]+"' js | head
grep -rhoaE 'useParams|route\.params|\$route\.params' js | head
```

### J3. Validation Gate -- Required / Format / Enum

```bash
grep -rhoaE '(required|message|pattern|enum|validator)\s*:' js | head
grep -rhoaE 'yup\.|zod\.|async-validator|Form\.Item|a-form-item|el-form-item' js | head
grep -rhoaE 'rules\s*:\s*\[|name:\s*["\'][a-zA-Z_]+["\']' js | head
grep -rhoaE 'label.*value|options\s*:\s*\[' js | head
```

### J4. Binding Layer -- Form to API

```bash
grep -rhoaE 'onFinish|handleSubmit|getFieldsValue|validateFields' js | head
grep -rhoaE '(pick|omit|transform|dayjs|moment)\(' js | head
```

Runtime supplement: DevTools -> Network -> Request -> **Initiator** (call stack) trace from `fetch`/`send` upward to find packaging function.

### J5. Encrypted Parameters

```bash
grep -rhoaE 'encrypt|decrypt|sign|CryptoJS|sm2|sm3|sm4|RSA|AES' js | head
```

**Do not guess fields from ciphertext** -- Hook the encryption function **inputs**, record plaintext payload before encryption; write conclusions to `config.json` / `param_candidates.json`.

### J6. Parameter Trigger Matrix (Phase 3 Required)

Record once per operation per module, diff request body/query:

| Operation | Focus |
|---|---|
| List first screen | Pagination default values |
| Search | keyword, filters |
| Advanced filter | optional fields |
| Create/edit | Complete entity |
| Batch/export | `ids[]`, `exportType` |
| Sort/paginate | `sortField`, `order` |

Output `param_samples.json`: `[{ "path", "method", "action": "search", "body", "query", "headers" }]`

### J7. Confidence Rules

| Confidence | Condition |
|---|---|
| **High** | Static callsite + runtime >=2 consistent samples |
| **Medium** | Static only, or only 1 runtime sample |
| **Low** | Response/error inference, not verified twice |
| **Pending trigger** | Statically known field, UI/permission not reached |

### J8. Scenario Quick Reference

| Scenario | Order |
|---|---|
| REST list page | J1 packaging object -> J6 four diffs -> J3 rules |
| Create/edit form | J3 Form name -> J4 submit chain -> runtime submit + intentionally leave empty to see 400 |
| GraphQL | J2 variables declaration -> runtime record variables per operation |
| Encrypted body | J5 Hook inputs -> pre-encryption fields are real params |

### J9. Mapping to api-recon Phases

| api-recon | Parameter recon |
|---|---|
| Phase 1 static | J1 anchor-window expansion |
| Phase 2 A2 interceptor | Globally injected fields (tenantId, sign) |
| Phase 3 runtime | J6 trigger matrix + `param_samples.json` |
| Phase 4 permission tree | Different module forms have different fields -> sufficient permissions needed to trigger all fields |
| Phase 5 merge | `params_merged.json` + confidence; do not determine required from single sample |

### J10. Troubleshooting

| Symptom | Resolution |
|---|---|
| Static has field name but runtime never shows it | Mark as "pending trigger"; supplement permission tree / click advanced filter / try each enum select option |
| Same path, different body shapes | Normal -- record separately by `action`, do not force-merge into one schema |
| Stub responses are fake but want to see params | **Look at outbound request** body/headers, do not infer from stub responses |
| 400 reports nested field | Note outer wrapping `data`/`bizData`/`variables` |
| GraphQL only shows operation name | Expand `variables` JSON; find `$var: Type` in static |
