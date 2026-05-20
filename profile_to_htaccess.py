#!/usr/bin/env python3
import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# Profile parsing
# ---------------------------------------------------------------------------

# `set key "value";` at any nesting level.
RX_SET = re.compile(r'^\s*set\s+([a-zA-Z0-9_]+)\s+"([^"]*)"\s*;', re.MULTILINE)

# Top-level http-* block openers.
RX_BLOCK = re.compile(r'^\s*(http-get|http-post|http-stager)\s*\{', re.MULTILINE)

# `client {` sub-block inside an http-* block.
RX_CLIENT_BLOCK = re.compile(r'\bclient\s*\{', re.MULTILINE)

# Generic `header "Name" "Value"` directive.
RX_HEADER_PAIR = re.compile(r'header\s+"([^"]+)"\s+"([^"]+)"')

# Headers we intentionally skip when building client-header match conditions.
#   User-Agent    — extracted separately, handled as ua_exact on the route.
#   Host          — extracted separately for the report ServerName suggestion.
#   Accept-Encoding — Apache / mod_deflate can rewrite this in transit,
#                     which causes false-negative mismatches on the redirector.
_SKIP_CLIENT_HEADERS = frozenset({'user-agent', 'host', 'accept-encoding'})


def _balanced_block(text: str, start: int) -> Optional[str]:
    """Return content inside the `{...}` starting at index `start`, or None."""
    if start >= len(text) or text[start] != '{':
        return None
    depth, i = 0, start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return None


def _split_uri_field(raw: str) -> List[str]:
    """
    `set uri` may contain multiple space-separated paths.
    Returns a list of normalised absolute paths.
    """
    result = []
    for part in raw.split():
        part = part.strip()
        if part:
            result.append(part if part.startswith('/') else f'/{part}')
    return result


def _extract_client_headers(block_body: str) -> Dict[str, str]:
    """
    Pull `header "Name" "Value"` directives from the `client {}` sub-block
    of an http-get or http-post block.  Skips headers in _SKIP_CLIENT_HEADERS.
    First occurrence of each header name wins (mirrors profile semantics).
    """
    m = RX_CLIENT_BLOCK.search(block_body)
    if not m:
        return {}
    brace_idx = block_body.rfind('{', 0, m.end())
    client_body = _balanced_block(block_body, brace_idx)
    if client_body is None:
        return {}

    headers: Dict[str, str] = {}
    for hm in RX_HEADER_PAIR.finditer(client_body):
        name  = hm.group(1).strip()
        value = hm.group(2).strip()
        if name.lower() in _SKIP_CLIENT_HEADERS:
            continue
        if name not in headers:
            headers[name] = value
    return headers


def parse_profile(profile_text: str) -> Dict[str, Any]:
    """
    Parse a malleable C2 profile into a plain dict.

    Returns
    -------
    {
        'useragent':              str | None,
        'extra_uas':              List[str],          # header "User-Agent" in blocks
        'http_get_uris':          List[str],           # supports space-sep multi-URI
        'http_get_client_headers': Dict[str, str],     # matched exactly in strict mode
        'http_post_uris':         List[str],
        'http_post_client_headers': Dict[str, str],
        'http_stager_uri_x86':    str | None,
        'http_stager_uri_x64':    str | None,
        'host_header':            str | None,
        'host_stage':             bool,               # True = staging enabled / unset
    }
    """
    result: Dict[str, Any] = {
        'useragent': None,
        'extra_uas': [],
        'http_get_uris': [],
        'http_get_client_headers': {},
        'http_post_uris': [],
        'http_post_client_headers': {},
        'http_stager_uri_x86': None,
        'http_stager_uri_x64': None,
        'host_header': None,
        'host_stage': True,   # staging on by default unless explicitly disabled
    }

    # Strip single-line comments before regex work.
    cleaned = re.sub(re.compile(r'#.*?\n'), '\n', profile_text)

    # Top-level directives.
    for m in RX_SET.finditer(cleaned):
        key, val = m.group(1), m.group(2)
        if key == 'useragent':
            result['useragent'] = val
        elif key == 'host_stage':
            result['host_stage'] = val.strip().lower() != 'false'

    # Walk each http-* block.
    for m in RX_BLOCK.finditer(cleaned):
        block_name = m.group(1)
        brace_idx  = cleaned.rfind('{', 0, m.end())
        body = _balanced_block(cleaned, brace_idx)
        if body is None:
            continue

        # URI extraction (may be multi-value, space-separated).
        for ms in RX_SET.finditer(body):
            key, val = ms.group(1), ms.group(2)
            if key == 'uri':
                uris = _split_uri_field(val)
                if block_name == 'http-get':
                    result['http_get_uris'].extend(uris)
                elif block_name == 'http-post':
                    result['http_post_uris'].extend(uris)
            elif key == 'uri_x86' and block_name == 'http-stager':
                result['http_stager_uri_x86'] = val
            elif key == 'uri_x64' and block_name == 'http-stager':
                result['http_stager_uri_x64'] = val

        # Extra User-Agent headers used by the beacon in this block.
        for hm in RX_HEADER_PAIR.finditer(body):
            if hm.group(1).strip().lower() == 'user-agent':
                ua = hm.group(2).strip()
                if ua and ua not in result['extra_uas']:
                    result['extra_uas'].append(ua)

        # Host header → ServerName suggestion in the report.
        for hm in re.finditer(r'header\s+"Host"\s+"([^"]+)"', body):
            result['host_header'] = hm.group(1)

        # Client-block headers for precise matching on profile URIs.
        if block_name == 'http-get':
            result['http_get_client_headers'] = _extract_client_headers(body)
        elif block_name == 'http-post':
            result['http_post_client_headers'] = _extract_client_headers(body)

    # De-duplicate URI lists (preserve order).
    for key in ('http_get_uris', 'http_post_uris'):
        seen: set = set()
        result[key] = [u for u in result[key] if not (u in seen or seen.add(u))]  # type: ignore[func-returns-value]

    return result


# ---------------------------------------------------------------------------
# Operator-editable config
# ---------------------------------------------------------------------------
# These lists are intentionally in the source file.  A future iteration will
# support loading them from an external YAML/TOML config.

GOOD_UA_PATTERNS: List[str] = [
    # Extra exact UAs to allow in addition to the profile's own UAs.
    # 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
]

BAD_UA_PATTERNS: List[str] = [
    # Generic CLI tools
    'curl', 'wget', 'python-requests', 'python-urllib', 'libwww',
    'Go-http-client', 'okhttp', 'Java/', 'apache-httpclient',
    'httpie', 'httpx', 'Wget',
    # Security tooling
    'nmap', 'masscan', 'zgrab', 'zmap', 'nikto', 'sqlmap', 'wpscan',
    'dirbuster', 'gobuster', 'ffuf', 'feroxbuster', 'wfuzz', 'dirsearch',
    'whatweb', 'wapiti', 'arachni', 'acunetix', 'netsparker', 'qualys',
    'rapid7', 'tenable', 'nessus', 'openvas', 'metasploit', 'burp',
    'OWASP', 'sslyze', 'testssl', 'nuclei', 'subfinder', 'amass',
    # Specific scanner fingerprints
    'censys', 'shodan', 'binaryedge', 'expanse', 'project25499',
    'l9scan', 'l9tcp', 'cortex-xpanse',
    # Search-engine / crawler bots
    'Googlebot', 'AdsBot', 'bingbot', 'YandexBot', 'DuckDuckBot',
    'Baiduspider', 'Slurp', 'facebookexternalhit', 'Twitterbot',
    'LinkedInBot', 'ia_archiver', 'AhrefsBot', 'SemrushBot', 'MJ12bot',
    'DotBot', 'PetalBot', 'SeznamBot', 'Applebot', 'CCBot',
    # Crawlers / archivers
    'archive.org_bot', 'Wayback', 'archive_org',
    # Fingerprint-free / blank
    'Mozilla/5.0 (compatible)',
    # Headless browsers
    'HeadlessChrome', 'PhantomJS', 'puppeteer', 'playwright',
    # Cloud health checks
    'AWS Health', 'Azure Health', 'GoogleHC', 'kube-probe',
    # Monitoring / uptime services
    'StatusCake', 'UptimeRobot', 'Pingdom', 'Site24x7',
    'New Relic', 'Datadog', 'NewRelicPinger',
]

# Paths no legitimate beacon traffic should ever touch.
# Evaluated AFTER profile proxy rules so .php URIs in the profile
# are already matched and proxied before this filter runs.
BAD_PATH_PATTERNS: List[str] = [
    r'\.env$', r'\.git/', r'\.svn/', r'\.DS_Store',
    r'^/wp-admin', r'^/wp-login', r'^/wp-includes', r'^/wordpress',
    r'^/admin', r'^/administrator', r'^/phpmyadmin', r'^/pma',
    r'^/manager/html', r'^/jmx-console', r'^/server-status',
    r'^/server-info', r'^/owa/', r'^/ews/',
    r'^/cgi-bin/', r'^/scripts/', r'^/_vti_bin/',
    r'\.aspx?$', r'\.jsp$', r'\.php$',
    r'/\.\./|/\.\.%2f',
    r'^/actuator',
    r'^/api/v1/(?!events/collect)',
    r'^/sitemap\.xml$', r'^/robots\.txt$',
]

POLICIES = ['none', 'lax', 'strict']


# ---------------------------------------------------------------------------
# ProxyRoute — the central abstraction
# ---------------------------------------------------------------------------

@dataclass
class ProxyRoute:
    """
    A single URI→backend proxy rule with all its match conditions resolved.

    Fields
    ------
    uri       Absolute path to match (e.g. '/static/foo.js').
    track     Origin of the route: 'profile-get', 'profile-post',
              'extra', or 'lax'.
    backend   Full backend URL (no trailing slash).
    ua_exact  Exact UA strings that satisfy the UA check (OR'd together).
              Empty list = no positive UA requirement.
    headers   {Header-Name: exact-value} conditions (AND'd with ua_exact).
              Only populated for profile tracks under strict policy.
    """
    uri:      str
    track:    str
    backend:  str
    ua_exact: List[str]         = field(default_factory=list)
    headers:  Dict[str, str]    = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Route building — ALL policy/track logic lives here
# ---------------------------------------------------------------------------

def build_routes(parsed:        Dict[str, Any],
                 backend:       str,
                 policy:        str,
                 operator_uas:  List[str],
                 extra_uris:    List[str],
                 lax_uris:      List[str]) -> List[ProxyRoute]:
    """
    Translate parsed profile data + operator options into an ordered list of
    ProxyRoute objects ready for rendering.

    This is the single source of truth for "which conditions apply to which
    URI track under which policy".  render_htaccess() never makes policy
    decisions — it just iterates what this function returns.

    UA scoping (Track 1 vs Track 2)
    --------------------------------
    profile_uas  — UAs extracted exclusively from the profile (`set useragent`
                   and `header "User-Agent"` in http-* blocks).  These are the
                   only UAs the beacon itself uses, so Track 1 (profile URIs)
                   matches ONLY these — no operator additions.

    extended_uas — profile_uas PLUS operator-supplied UAs (--allow-ua / the
                   GOOD_UA_PATTERNS list).  Used for Track 2 (extra URIs)
                   where client shape is unknown and operators may be staging
                   payloads with a different tool/UA.
    """
    routes: List[ProxyRoute] = []

    # UAs that the beacon itself uses — sourced only from the profile.
    profile_uas = _unique_nonempty(
        ([parsed['useragent']] if parsed.get('useragent') else [])
        + parsed.get('extra_uas', [])
    )

    # For Track 2: profile UAs + operator-supplied UAs (e.g. a PowerShell
    # stager UA passed via --allow-ua).
    extended_uas = _unique_nonempty(profile_uas + operator_uas)

    # Positive UA matching is only enforced under strict policy.
    ua_track1 = profile_uas  if policy == 'strict' else []
    ua_track2 = extended_uas if policy == 'strict' else []

    # ------------------------------------------------------------------
    # Track 1 — Profile URIs (http-get, http-post)
    # The malleable profile is a contract: we know exactly what the beacon
    # sends.  Under strict policy we match the beacon's own UAs + every
    # client-block header (except the skipped ones).
    # Operator --allow-ua values do NOT appear here — they are staging/
    # tooling UAs that have no business on beacon comms endpoints.
    # ------------------------------------------------------------------
    get_headers  = parsed.get('http_get_client_headers',  {}) if policy == 'strict' else {}
    post_headers = parsed.get('http_post_client_headers', {}) if policy == 'strict' else {}

    for uri in parsed.get('http_get_uris', []):
        routes.append(ProxyRoute(
            uri=uri, track='profile-get', backend=backend,
            ua_exact=list(ua_track1), headers=dict(get_headers),
        ))

    for uri in parsed.get('http_post_uris', []):
        routes.append(ProxyRoute(
            uri=uri, track='profile-post', backend=backend,
            ua_exact=list(ua_track1), headers=dict(post_headers),
        ))

    # ------------------------------------------------------------------
    # Track 2 — Operator extra URIs
    # Could be payload drops, PowerShell scripts, callbacks.  Client shape
    # is unknown so no header matching.  UA enforcement uses extended_uas
    # (profile UAs + operator UAs) under strict policy.
    # ------------------------------------------------------------------
    for uri in extra_uris:
        routes.append(ProxyRoute(
            uri=uri, track='extra', backend=backend,
            ua_exact=list(ua_track2), headers={},
        ))

    # ------------------------------------------------------------------
    # Track 3 — Lax URIs
    # No positive conditions.  The global bad-UA blacklist (when policy !=
    # none) is the only gate.  Maximum permissiveness.
    # ------------------------------------------------------------------
    for uri in lax_uris:
        routes.append(ProxyRoute(
            uri=uri, track='lax', backend=backend,
            ua_exact=[], headers={},
        ))

    return routes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _re_escape_path(s: str) -> str:
    return re.escape(s)


def _unique_nonempty(values: List[Optional[str]]) -> List[str]:
    """Deduplicate while preserving insertion order, dropping falsy values."""
    seen: set = set()
    result = []
    for v in values:
        if isinstance(v, str):
            v = v.strip()
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _normalize_uris(values: Optional[List[str]]) -> List[str]:
    return _unique_nonempty([
        v if v.startswith('/') else f'/{v}' for v in (values or [])
    ])


def _policy_from_legacy_ua_match(v: str) -> str:
    return {'off': 'none', 'none': 'none', 'on': 'strict',
            'strict': 'strict', 'relaxed': 'strict'}[v]


def _policy_from_legacy_global_policy(v: str) -> str:
    return {'global-none': 'none', 'global-lax': 'lax',
            'global-whitelist': 'strict', 'global-strict': 'strict',
            'none': 'none', 'lax': 'lax', 'strict': 'strict'}[v]


# ---------------------------------------------------------------------------
# Operator report
# ---------------------------------------------------------------------------

def print_run_report(parsed:        Dict[str, Any],
                     routes:        List[ProxyRoute],
                     backend:       str,
                     decoy:         str,
                     forbid_http:   bool,
                     policy:        str,
                     good_uas:      List[str],
                     bad_uas:       List[str],
                     output:        Optional[Path],
                     server_name:   str,
                     document_root: str,
                     site_name:     str) -> None:
    """Print a compact operator summary to stderr."""
    def e(*args): print(*args, file=sys.stderr)

    backend_ssl = 'yes' if backend.lower().startswith('https://') else 'no'
    site_conf   = f'{site_name}.conf'

    e('')
    e('=== malleable-redirector / profile_to_htaccess ===')
    e(f"output:        {output or 'stdout'}")
    e(f'policy:        {policy}')
    e(f'backend:       {backend}')
    e(f'decoy:         {decoy}')
    e(f'server name:   {server_name}')
    e(f'document root: {document_root}')
    e(f'forbid HTTP:   {forbid_http}')
    e(f'backend TLS:   {backend_ssl}')
    e('')

    e('profile:')
    e(f"  useragent:   {parsed['useragent']!r}")

    extra_uas = parsed.get('extra_uas', [])
    if extra_uas:
        e(f'  extra UAs from profile headers ({len(extra_uas)}):')
        for ua in extra_uas:
            e(f'    {ua!r}')

    get_uris  = parsed.get('http_get_uris',  [])
    post_uris = parsed.get('http_post_uris', [])
    e(f"  http-get URIs ({len(get_uris)}):  {get_uris or 'none'}")
    if policy == 'strict' and parsed.get('http_get_client_headers'):
        e(f"  http-get headers: {parsed['http_get_client_headers']}")
    e(f"  http-post URIs ({len(post_uris)}): {post_uris or 'none'}")
    if policy == 'strict' and parsed.get('http_post_client_headers'):
        e(f"  http-post headers: {parsed['http_post_client_headers']}")

    if parsed.get('http_stager_uri_x64') or parsed.get('http_stager_uri_x86'):
        e(f"  stager x64:  {parsed['http_stager_uri_x64']!r}")
        e(f"  stager x86:  {parsed['http_stager_uri_x86']!r}")

    staging = ('ENABLED — staging traffic will NOT be proxied (see warning above)'
               if parsed.get('host_stage') else 'disabled')
    e(f'  host_stage:  {staging}')
    e('')

    e('routes:')
    for track in ('profile-get', 'profile-post', 'extra', 'lax'):
        track_routes = [r for r in routes if r.track == track]
        if track_routes:
            e(f'  {track} ({len(track_routes)}):')
            for r in track_routes:
                cond_summary = f'UA×{len(r.ua_exact)} + headers×{len(r.headers)}' if r.ua_exact or r.headers else 'no conditions'
                e(f'    {r.uri}  [{cond_summary}]')
    e(f'  operator UAs (Track 2 only): {good_uas or "none"}')
    e(f'  block UAs:  {len(bad_uas)}')
    e('')

    e('setup:')
    e('  sudo a2enmod rewrite proxy proxy_http ssl headers')
    e('  # apache2.conf hardening: ServerTokens Prod / ServerSignature Off')
    e(f'  # .htaccess → {document_root}/.htaccess')
    e(f'  # site config → /etc/apache2/sites-available/{site_conf}')
    e('')

    e('# Suggested VirtualHost snippet:')
    if forbid_http:
        e(f'<VirtualHost *:80>')
        e(f'    ServerName {server_name}')
        e( '    <Location />')
        e( '        Require all denied')
        e( '    </Location>')
        e( '</VirtualHost>')
    else:
        e( '<VirtualHost *:80>')
        e(f'    ServerName {server_name}')
        e(f'    DocumentRoot {document_root}')
        e(f'    <Directory {document_root}>')
        e( '        Options -Indexes +FollowSymLinks')
        e( '        AllowOverride All')
        e( '        Require all granted')
        e( '    </Directory>')
        e( '</VirtualHost>')
    e('')
    e( '<VirtualHost *:443>')
    e(f'    ServerName {server_name}')
    e( '    SSLEngine on')
    e(f'    SSLCertificateFile /etc/letsencrypt/live/{server_name}/fullchain.pem')
    e(f'    SSLCertificateKeyFile /etc/letsencrypt/live/{server_name}/privkey.pem')
    e(f'    DocumentRoot {document_root}')
    e(f'    <Directory {document_root}>')
    e( '        Options -Indexes +FollowSymLinks')
    e( '        AllowOverride All')
    e( '        Require all granted')
    e( '    </Directory>')
    if backend.lower().startswith('https://'):
        e( '    SSLProxyEngine On')
        e( '    SSLProxyVerify none')
        e( '    SSLProxyCheckPeerName off')
        e( '    SSLProxyCheckPeerCN off')
        e( '    SSLProxyCheckPeerExpire off')
    e( '    Header always unset X-Powered-By')
    e( '    Header always unset Server')
    e( '</VirtualHost>')
    e('')
    e(f'  sudo a2ensite {site_conf}')
    e( '  sudo apachectl configtest && sudo systemctl reload apache2')
    e('===================================================')


# ---------------------------------------------------------------------------
# .htaccess emission
# ---------------------------------------------------------------------------

_TRACK_LABELS: Dict[str, str] = {
    'profile-get':  'profile http-get',
    'profile-post': 'profile http-post',
    'extra':        'extra URI',
    'lax':          'lax URI',
}


def _emit_bad_ua_block(out: List[str], decoy: str, bad_uas: List[str]) -> None:
    """
    Emit the global bad-UA redirect block.
    Any request whose UA matches a blocked substring, or has an empty/dash UA,
    is immediately redirected to the decoy.  Runs before proxy routes.
    """
    P = out.append
    for ua in bad_uas:
        P(f'RewriteCond %{{HTTP_USER_AGENT}} {re.escape(ua)} [NC,OR]')
    # ^-?$ catches both empty string and a bare dash (some scanners).
    P('RewriteCond %{HTTP_USER_AGENT} ^-?$')
    P(f'RewriteRule ^.*$ {decoy} [R=302,L]')


def _emit_route(out: List[str], route: ProxyRoute) -> None:
    """
    Emit Apache mod_rewrite directives for one ProxyRoute.

    Condition logic:
      UA conditions are OR'd:   (UA1 OR UA2 OR … OR UAn)
      Header conditions AND'd:  AND Accept=… AND Referer=… …
    Combined:  (any allowed UA) AND (all expected headers) → proxy.

    In .htaccess context the leading slash is stripped from RewriteRule
    patterns but kept in the substitution URL.
    """
    P = out.append
    label = _TRACK_LABELS.get(route.track, route.track)
    P(f'# [{label}] {route.uri}')

    # UA allow-list: OR'd so any single matching UA passes the check.
    for i, ua in enumerate(route.ua_exact):
        flag = ' [OR]' if i < len(route.ua_exact) - 1 else ''
        P(f'RewriteCond %{{HTTP_USER_AGENT}} ^{re.escape(ua)}${flag}')

    # Client header conditions: AND'd with the UA group.
    # Uses %{HTTP:Name} which works for any header name, standard or custom.
    for header, value in route.headers.items():
        P(f'RewriteCond %{{HTTP:{header}}} ^{re.escape(value)}$')

    uri_rx = re.escape(route.uri.lstrip('/'))
    P(f'RewriteRule ^{uri_rx}$ {route.backend}{route.uri} [P,L]')


def render_htaccess(profile_name: str,
                    routes:       List[ProxyRoute],
                    decoy:        str,
                    policy:       str,
                    bad_uas:      List[str],
                    forbid_http:  bool = False) -> str:
    """
    Build the final .htaccess string.

    This function is intentionally free of policy logic — it only decides
    *ordering* of sections and delegates per-route emission to _emit_route().
    All "what conditions go where" decisions were made in build_routes().
    """
    out: List[str] = []
    P = out.append

    P('# -----------------------------------------------------------------')
    P(f'# .htaccess generated from {profile_name}')
    P('# Tool: malleable-redirector / profile_to_htaccess.py')
    P('# DO NOT EDIT BY HAND — regenerate via:')
    P(f'#     python3 profile_to_htaccess.py {profile_name} -o .htaccess')
    P('#')
    P('# Required Apache modules (enable in apache2.conf, not here):')
    P('#     mod_rewrite  mod_proxy  mod_proxy_http  mod_ssl  mod_headers')
    P(f'# Policy: {policy}')
    P('# Staging rules: NOT generated (add `set host_stage "false";`)')
    P('# -----------------------------------------------------------------')
    P('')
    P('RewriteEngine On')
    P('Options -Indexes +FollowSymLinks')
    P('')

    # ---- 0. Forbid plain HTTP -------------------------------------------
    if forbid_http:
        P('# ---- 0. Forbid plain HTTP ------')
        P('RewriteCond %{HTTPS} !=on')
        P('RewriteRule ^.*$ - [F,L]')
        P('')

    # ---- 1. Global bad-UA blacklist (lax + strict) ----------------------
    if policy in ('lax', 'strict'):
        P(f'# ---- 1. Bad-UA blacklist ({len(bad_uas)} entries) ------')
        _emit_bad_ua_block(out, decoy, bad_uas)
        P('')

    # ---- 2. Strict pre-route guards ------------------------------------
    if policy == 'strict':
        P('# ---- 2a. Direct-IP guard ------')
        P('RewriteCond %{HTTP_HOST} ^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})?$')
        P(f'RewriteRule ^.*$ {decoy} [R=302,L]')
        P('')
        P('# ---- 2b. Method guard (GET and POST only) ------')
        P('RewriteCond %{REQUEST_METHOD} !^(GET|POST)$')
        P(f'RewriteRule ^.*$ {decoy} [R=302,L]')
        P('')

    # ---- 3. Proxy routes -----------------------------------------------
    # Intentionally before the probe path filter so profile URIs that happen
    # to match a bad-path pattern (e.g. .php endpoints) are proxied first.
    if routes:
        P('# ---- 3. Proxy routes ------')
        for route in routes:
            P('')
            _emit_route(out, route)
        P('')
    else:
        P('# ---- 3. Proxy routes (none defined) ------')
        P('')

    # ---- 4. Probe path filter (strict, AFTER routes) -------------------
    if policy == 'strict':
        P('# ---- 4. Probe path filter ------')
        P('# Runs after proxy rules — profile URIs matching these patterns')
        P('# (e.g. .php paths) are already proxied above and never reach here.')
        for pat in BAD_PATH_PATTERNS:
            P(f'RewriteCond %{{REQUEST_URI}} {pat} [NC,OR]')
        out[-1] = out[-1].replace(' [NC,OR]', ' [NC]')
        P(f'RewriteRule ^.*$ {decoy} [R=302,L]')
        P('')

    # ---- 5. Catch-all --------------------------------------------------
    P('# ---- 5. Catch-all ------')
    P(f'RewriteRule ^.*$ {decoy} [R=302,L]')

    return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description='malleable-redirector: Apache .htaccess from a '
                    'Cobalt Strike malleable C2 profile.')

    ap.add_argument('profile', type=Path, help='path to .profile file')
    ap.add_argument('--backend', default='https://teamserver.internal:443',
                    help='backend team-server URL (no trailing slash)')
    ap.add_argument('--decoy', default='https://www.example.com/',
                    help='redirect non-matching traffic here')
    ap.add_argument('-o', '--output', type=Path, default=None,
                    help='output file (default: stdout)')
    ap.add_argument('--server-name', default=None,
                    help='ServerName for the setup report '
                         '(defaults to profile Host header or placeholder)')
    ap.add_argument('--document-root', default='/var/www/redirector',
                    help='DocumentRoot for the setup report')
    ap.add_argument('--site-name', default='redirector',
                    help='Apache site config basename for the setup report')

    ap.add_argument('--forbid-http', dest='forbid_http', action='store_true',
                    help='emit a 403 rule for plain HTTP traffic')
    ap.add_argument('--force-https', dest='forbid_http', action='store_true',
                    help=argparse.SUPPRESS)

    ap.add_argument('--extra-uri', action='append', default=[], metavar='PATH',
                    help='Track 2 URI (policy UA check, no header match). Repeatable.')
    ap.add_argument('--lax-uri', action='append', dest='lax_uri', default=[],
                    metavar='PATH',
                    help='Track 3 URI (no positive conditions). Repeatable.')
    ap.add_argument('--extra-uri-open', action='append', dest='lax_uri',
                    default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    ap.add_argument('--url-lax', action='append', dest='lax_uri',
                    default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    ap.add_argument('--policy', choices=POLICIES, default='strict',
                    help='strict (default) | lax | none')
    ap.add_argument('--global-policy',
                    choices=['global-none','global-lax','global-whitelist',
                             'global-strict','none','lax','strict'],
                    default=None, help=argparse.SUPPRESS)
    ap.add_argument('--ua-match',
                    choices=['on','off','strict','none','relaxed'],
                    default=None, help=argparse.SUPPRESS)

    ap.add_argument('--allow-ua', action='append', dest='allow_ua', default=[],
                    metavar='STRING',
                    help='extra exact UA to allow on strict routes. Repeatable.')
    ap.add_argument('--good-ua', action='append', dest='allow_ua',
                    default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    ap.add_argument('--block-ua', action='append', dest='block_ua', default=[],
                    metavar='STRING',
                    help='extra bad-UA substring to block. Repeatable.')
    ap.add_argument('--bad-ua', action='append', dest='block_ua',
                    default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    args = ap.parse_args(argv)

    # Legacy flag compat.
    if args.global_policy is not None:
        args.policy = _policy_from_legacy_global_policy(args.global_policy)
        print(f'warning: --global-policy {args.global_policy!r} → '
              f'--policy {args.policy}', file=sys.stderr)
    if args.ua_match is not None:
        args.policy = _policy_from_legacy_ua_match(args.ua_match)
        print(f'warning: --ua-match {args.ua_match!r} → '
              f'--policy {args.policy}', file=sys.stderr)

    if not args.profile.is_file():
        print(f'error: profile not found: {args.profile}', file=sys.stderr)
        return 1

    if args.backend.endswith('/'):
        args.backend = args.backend.rstrip('/')

    profile_text = args.profile.read_text(encoding='utf-8', errors='replace')
    parsed = parse_profile(profile_text)

    # Staging warning — printed before everything else so it's hard to miss.
    if parsed.get('host_stage', True):
        print('', file=sys.stderr)
        print('[!] WARNING: Beacon staging is ENABLED in this profile (or not',  file=sys.stderr)
        print('    explicitly disabled).  malleable-redirector does NOT generate', file=sys.stderr)
        print('    staging rules.  Staging traffic (/....) will NOT be proxied', file=sys.stderr)
        print('    to your backend — it will fall through to the decoy redirect.', file=sys.stderr)
        print('    To suppress this warning add to your profile:', file=sys.stderr)
        print('', file=sys.stderr)
        print('        set host_stage "false";', file=sys.stderr)
        print('', file=sys.stderr)

    # operator_uas: UAs supplied by the operator via --allow-ua or GOOD_UA_PATTERNS.
    # These are NOT beacon UAs — they are tooling/staging UAs (e.g. a PowerShell
    # stager) that should only be allowed on Track 2 (extra URIs), not Track 1
    # (profile beacon comms).  The profile's own extra_uas are handled internally
    # by build_routes() via the parsed dict.
    operator_uas        = _unique_nonempty(GOOD_UA_PATTERNS + args.allow_ua)
    configured_bad_uas  = _unique_nonempty(BAD_UA_PATTERNS + args.block_ua)
    extra_uris  = _normalize_uris(args.extra_uri)
    lax_uris    = _normalize_uris(args.lax_uri)
    server_name = (args.server_name
                   or parsed.get('host_header')
                   or 'your-c2-host.example.com')

    if not parsed['http_get_uris'] and not parsed['http_post_uris']:
        print('warning: no http-get/http-post URIs found — all traffic will '
              'redirect to the decoy.', file=sys.stderr)

    # Build routes (all logic here).
    routes = build_routes(
        parsed, args.backend, args.policy,
        operator_uas, extra_uris, lax_uris,
    )

    print_run_report(
        parsed, routes, args.backend, args.decoy, args.forbid_http,
        args.policy, operator_uas, configured_bad_uas, args.output,
        server_name, args.document_root, args.site_name,
    )

    # Render (no logic here).
    body = render_htaccess(
        profile_name=args.profile.name,
        routes=routes,
        decoy=args.decoy,
        policy=args.policy,
        bad_uas=configured_bad_uas,
        forbid_http=args.forbid_http,
    )

    if args.output:
        args.output.write_text(body, encoding='utf-8')
        print(f'[ok] wrote {len(body)} bytes to {args.output}', file=sys.stderr)
    else:
        sys.stdout.write(body)

    return 0


if __name__ == '__main__':
    sys.exit(main())
