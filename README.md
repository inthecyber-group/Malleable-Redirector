# Malleable Redirector

Apache `.htaccess` redirector generation from Cobalt Strike malleable C2 profiles.

Malleable Redirector parses a CS malleable profile and emits a hardened `.htaccess` that proxies only legitimate beacon traffic to your team server, sending everything else, scanners, bots, blue team probes, to a convincing decoy. It understands the profile DSL well enough to enforce exact header matching on beacon comms endpoints, not just UA filtering.

*Intended for authorised red team engagements only.*



## Features

- **Precise header matching on beacon routes.** Extracts every `client {}` header from the profile (`Accept`, `Accept-Language`, `Content-Type`, etc.) and enforces them as `RewriteCond` on the exact URIs where the beacon sends them. A scanner with the right UA still gets turned away if it doesn't send the right headers.

- **Three-track URI model.** Profile URIs (beacon comms), operator-added staging URIs, and lax/unconditional URIs each get their own track with appropriate matching, no one-size-fits-all policy.

- **Correct rule ordering.** Profile proxy rules run *before* the probe path filter, so `.php` or `.aspx` URIs in your profile are proxied rather than blocked by the probe filter that comes after.

- **UA scope separation.** Operator-supplied `--allow-ua` values (e.g. a PowerShell stager UA) only apply to staging URIs, not to beacon comms endpoints. Your C2 traffic gate is not widened by your staging setup.

- **Multi-URI support.** `set uri "/path1 /path2";` is correctly split into separate routes.

- **Staging awareness.** If your profile doesn't set `host_stage "false"`, the tool warns loudly before generation. Staging rules are not generated, by design.



## How it works

### Three-track URI model

| Track | Source | UA matching | Header matching |
|-------|--------|-------------|-----------------|
| **Track 1 — profile** | `http-get` / `http-post` URIs parsed from the profile | Beacon UAs from profile only | All `client {}` headers (strict policy) |
| **Track 2 — extra** | `--extra-uri` operator flags | Beacon UAs + operator `--allow-ua` (strict policy) | None |
| **Track 3 — lax** | `--lax-uri` operator flags | None | None |

Different traffic on your redirector carries different levels of certainty: you know exactly what your beacon will send, but you can't always predict the shape of a staging request. The three tracks translate that operational reality into distinct rule sets. A detailed breakdown is covered in the accompanying Medium article.

### Policy modes

| Policy | Bad-UA blacklist | Direct-IP guard | Method guard | UA check | Header check |
|--------|-----------------|-----------------|--------------|----------|--------------|
| `strict` (default) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `lax` | ✓ | — | — | — | — |
| `none` | — | — | — | — | — |

`strict` is the intended operational mode. `lax` and `none` exist for testing or environments where access is already controlled at the network layer.

### Rule order

Rules are emitted in this fixed order so each gate is evaluated before the next:

```
0  Forbid plain HTTP          (--forbid-http)
1  Global bad-UA blacklist    (strict + lax)
2a Direct-IP guard            (strict)
2b Method guard GET|POST      (strict)
3  Proxy routes               (all tracks, BEFORE probe filter)
4  Probe path filter          (strict, after proxy routes)
5  Catch-all → decoy
```

The probe path filter (section 4) intentionally comes after proxy routes (section 3), a `.php` or `.aspx` URI in your malleable profile is proxied before the filter ever sees it.



## Setup and usage

**A Sample Malleable C2 profile was included in the repository for your testing pleasure**

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

For a more complete operator setup with staging URIs and an allow-listed stager UA:

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

The tool prints a full operator report and a ready-to-use Apache VirtualHost snippet to stderr.

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
| `--extra-uri PATH` | — | Repeatable. Track 2 URI — UA check, no header matching. |
| `--lax-uri PATH` | — | Repeatable. Track 3 URI — no positive conditions. |
| `--allow-ua STRING` | — | Repeatable. Exact UA for Track 2 only. Does not affect beacon comms routes. |
| `--block-ua STRING` | — | Repeatable. Extra substring added to the bad-UA blacklist. |
| `--server-name NAME` | profile `Host` header | For the setup report only. |
| `--document-root PATH` | `/var/www/redirector` | For the setup report only. |
| `--site-name NAME` | `redirector` | For the setup report only. |



## Limitations

- **Beacon staging rules are not generated.** If your profile has `host_stage` enabled (or unset), the tool warns before generating. Add `set host_stage "false";` to suppress. Staging from a redirector adds operational complexity with limited benefit.

- **nginx is not yet supported.** The internal `parse → build_routes → render` pipeline is designed for it, nginx support requires only a new renderer, no changes to parsing or route logic.



## Credits

Thanks to the team behind [cs2modrewrite](https://github.com/threatexpress/cs2modrewrite) for their inspiration.
