# Malleable Redirector

Apache `.htaccess` redirector generator for Cobalt Strike Malleable C2 profiles.

Malleable Redirector parses a Cobalt Strike Malleable C2 profile and emits a hardened `.htaccess` file. It proxies only profile-matching beacon traffic to your team server. Everything else, including scanners, bots, and blue-team probes, is redirected to a convincing decoy.

It understands the profile DSL well enough to enforce exact header matching on beacon comms endpoints, not just User-Agent (UA) filtering.

*Intended for authorised red team engagements only.*

## Features

- **Precise header matching on beacon routes.** Extracts every `client {}` header from the profile (`Accept`, `Accept-Language`, `Content-Type`, etc.) and enforces them as `RewriteCond` on the exact URIs where the beacon sends them. A scanner with the right UA still gets turned away if it doesn't send the right headers.

- **URI-specific routing policy.** Generated rules do not treat every path the same. Profile-derived beacon endpoints are locked to the profile's user agents and `client {}` headers; operator-added extra paths can accept extra `--allow-ua` values without weakening beacon routes; and explicitly lax paths, such as health checks, can be proxied without required UA or header checks when you ask for that behavior.

- **Correct rule ordering.** Profile proxy rules run *before* the probe path filter, so `.php` or `.aspx` URIs in your profile are proxied rather than blocked by the probe filter that comes after.

- **UA scope separation.** Operator-supplied `--allow-ua` values (e.g. a PowerShell stager UA) only apply to extra operator URIs, not to beacon comms endpoints. Your C2 traffic gate is not widened by your staging setup.

- **Multi-URI support.** `set uri "/path1 /path2";` is correctly split into separate routes.

- **Staging awareness.** If your profile doesn't set `host_stage "false"`, the tool warns loudly before generation. Automatic Cobalt Strike staging rules are not generated, by design.

## How it works

### Three-track URI model

| Track | Source | UA matching | Header matching |
|-------|--------|-------------|-----------------|
| **Track 1 — profile** | `http-get` / `http-post` URIs parsed from the profile | Beacon UAs from profile only | All `client {}` headers (strict policy) |
| **Track 2 — extra** | `--extra-uri` operator flags for manually added staging or payload routes | Beacon UAs + operator `--allow-ua` (strict policy) | None |
| **Track 3 — lax** | `--lax-uri` operator flags | None | None |

Different traffic on your redirector carries different levels of certainty: you know exactly what your beacon will send, but you cannot always predict the shape of a staging or operator-added request. The three tracks translate that operational reality into distinct rule sets.

### Policy modes

| Policy | Bad-UA blocklist | Direct-IP guard | Method guard | UA check | Profile header check |
|--------|------------------|-----------------|--------------|----------|----------------------|
| `strict` (default) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `lax` | ✓ | — | — | — | — |
| `none` | — | — | — | — | — |

`strict` is the intended operational mode. `lax` and `none` exist for testing or environments where access is already controlled at the network layer.

### Rule order

Rules are emitted in this fixed order so each gate is evaluated before the next:

```
0  Forbid plain HTTP          (--forbid-http)
1  Global bad-UA blocklist    (strict + lax)
2a Direct-IP guard            (strict)
2b Method guard GET|POST      (strict)
3  Proxy routes               (all tracks, BEFORE probe filter)
4  Probe path filter          (strict, after proxy routes)
5  Catch-all → decoy
```

The probe path filter (section 4) intentionally comes after proxy routes (section 3), so a `.php` or `.aspx` URI in your malleable profile is proxied before the filter ever sees it.

## Setup and usage

A sample Malleable C2 profile, `chches_APT10.profile`, is included for testing.

### Requirements

- Python 3.7+ — pure stdlib, no third-party dependencies
- Apache 2.4 with modules: `mod_rewrite`, `mod_proxy`, `mod_proxy_http`, `mod_ssl`, `mod_headers`

### Installation

```bash
git clone https://github.com/InTheCyber/malleable-redirector
cd malleable-redirector
```

### Generate the .htaccess

Run the tool against your profile, pointing it at your team server and a decoy:

```bash
python3 profile_to_htaccess.py current.profile \
    --backend  https://teamserver.internal:443 \
    --decoy    https://www.legit-looking-site.com/ \
    --policy   strict \
    --forbid-http \
    -o .htaccess
```

For a more complete operator setup with extra operator URIs and an allow-listed stager UA:

```bash
python3 profile_to_htaccess.py ops.profile \
    --backend   https://10.10.10.5:443 \
    --decoy     https://www.microsoft.com/ \
    --forbid-http \
    --policy    strict \
    --extra-uri /cdn/update.cab \
    --extra-uri /telemetry/v2/push \
    --lax-uri   /health \
    --allow-ua  "PowerShell/5.1 (Windows NT 10.0; Win64; x64)" \
    --server-name redirector.contoso-infra.com \
    --document-root /var/www/html \
    -o /var/www/html/.htaccess
```

The tool prints a full operator report and a ready-to-use Apache VirtualHost snippet to stderr, leaving stdout free for `.htaccess` output when `-o` is not used.

### Deploy on the redirector

Enable the required Apache modules:

```bash
sudo a2enmod rewrite proxy proxy_http ssl headers
```

Harden the server identity in `/etc/apache2/conf-available/security.conf`:

```
ServerTokens Prod
ServerSignature Off
```

Drop the generated `.htaccess` into your `DocumentRoot` and configure the VirtualHost (the tool prints a tailored snippet to stderr, but the general structure is):

```apache
<VirtualHost *:80>
    ServerName redirector.example.com
    <Location />
        Require all denied
    </Location>
</VirtualHost>

<VirtualHost *:443>
    ServerName redirector.example.com

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/redirector.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/redirector.example.com/privkey.pem

    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Required if team server uses a self-signed certificate
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerExpire off

    Header always unset X-Powered-By
    Header always unset Server
</VirtualHost>
```

Enable and reload:

```bash
sudo a2ensite redirector.conf
sudo apachectl configtest && sudo systemctl reload apache2
```

## CLI reference

```
usage: profile_to_htaccess.py profile [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `profile` | — | Path to the `.profile` file |
| `--backend URL` | `https://teamserver.internal:443` | Team server URL. No trailing slash. |
| `--decoy URL` | `https://www.example.com/` | Non-matching traffic redirects here (302). |
| `-o / --output PATH` | stdout | Write `.htaccess` to file. |
| `--forbid-http` | off | Return 403 on plain HTTP. |
| `--policy` | `strict` | `strict` / `lax` / `none` |
| `--extra-uri PATH` | — | Repeatable. Track 2 URI — required UA check, no profile header matching. |
| `--lax-uri PATH` | — | Repeatable. Track 3 URI — no required UA or header checks. |
| `--allow-ua STRING` | — | Repeatable. Exact UA for Track 2 only. Does not affect beacon comms routes. |
| `--block-ua STRING` | — | Repeatable. Extra substring added to the bad-UA blocklist. |
| `--server-name NAME` | profile `Host` header | For the setup report only. |
| `--document-root PATH` | `/var/www/redirector` | For the setup report only. |
| `--site-name NAME` | `redirector` | For the setup report only. |

## Limitations

- **Beacon staging rules are not generated.** If your profile has `host_stage` enabled (or unset), the tool warns before generating. Add `set host_stage "false";` to suppress. Automatic staging from a redirector adds operational complexity with limited benefit.

- **nginx is not yet supported.** The internal `parse → build_routes → render` pipeline is designed for it, nginx support requires only a new renderer, no changes to parsing or route logic.

## Credits

Thanks to the team behind [cs2modrewrite](https://github.com/threatexpress/cs2modrewrite) for their inspiration.
