# Running the relay

The relay is the one public piece of a warren setup. It needs a host with a
public IP address, TCP port 443 reachable from everywhere your machines are,
and, if you use automatic certificates, TCP port 80. It holds no private keys
of your machines and cannot read private links; it does see published (public)
traffic, because it terminates TLS for it.

## Command line

```
warren relay --domain relay.example.com [certificate source] [options]
```

| flag | default | meaning |
|---|---|---|
| `--domain HOST` | required | the relay's own host name; nodes use `https://HOST` and sign it into every login |
| `--publish-domain DOMAIN` | `--domain` | published names live at `NAME.DOMAIN` |
| `--listen ADDR` | `0.0.0.0:443` | TLS listener for nodes and published names (IPv4; see *DNS records* for IPv6) |
| `--state DIR` | `$WARREN_HOME/relay` or `~/.warren/relay` | state directory (created `0700`) |
| `--acme EMAIL` | | automatic certificates from an ACME CA (Let's Encrypt by default) |
| `--acme-directory URL` | Let's Encrypt production | another ACME directory (e.g. a staging CA) |
| `--http-listen ADDR` | `0.0.0.0:80` with `--acme` | plain-HTTP listener: ACME challenges, redirects to HTTPS (IPv4 by default) |
| `--cert FILE --key FILE` | | a PEM certificate chain and key used for every name |
| `--self-signed` | | a persistent self-signed certificate, for testing |
| `--json` | | print the startup event as JSON |

Exactly one certificate source is required. `WARREN_LOG=debug` makes
warren's own log more verbose (libraries stay at `warn` at any setting, so
enrollment codes and published traffic never reach the log); logs go to
stderr.

Nodes must be configured with the same host name as `--domain`: their login
signatures cover it, which stops a signature made for one relay from being
used on another.

## DNS records

For a relay at `relay.example.com` whose published names live under the same
domain:

```
relay.example.com.     A      203.0.113.10
relay.example.com.     AAAA   2001:db8::10          ; if the host has IPv6
*.relay.example.com.   A      203.0.113.10          ; published names
*.relay.example.com.   AAAA   2001:db8::10
```

The default listeners are IPv4 only. If you publish AAAA records, make the
relay listen on IPv6 too, or clients (and the ACME CA, which prefers IPv6)
first hit a refused connection:

```sh
warren relay --domain relay.example.com --acme you@example.com \
    --listen '[::]:443' --http-listen '[::]:80' --state /var/lib/warren
```

On Linux (with the default `net.ipv6.bindv6only=0`) an `[::]` listener also
accepts IPv4. Without AAAA records, keep the defaults.

Instead of the wildcard you can add one record per published name. With
`--publish-domain apps.example.com`, the wildcard goes under
`*.apps.example.com` instead.

**Custom domains.** To serve `www.example.org` as the published name `web`:

```sh
warren relay domain add www.example.org web --state /var/lib/warren
```

and point `www.example.org` at the relay (A/AAAA, or a CNAME to
`relay.example.com`). `warren relay domain list` and `domain remove HOST`
manage the mapping. Only the relay operator can add custom domains; nodes can
only claim names under the publish domain.

## Certificates

### Automatic (ACME)

```sh
warren relay --domain relay.example.com --acme you@example.com --state /var/lib/warren
```

* Uses the ACME HTTP-01 challenge, answered on port 80, so no wildcard
  certificate and no DNS API are needed.
* One certificate per host name: the relay's own domain at startup, each
  published name on its first claim, each custom domain when added.
* Certificates are renewed when fewer than 30 days of validity remain (checked
  twice a day).
* The ACME account key and the certificates live in `STATE/certs/` (`0600`).
* Until a name's certificate has been issued, TLS handshakes for it fail;
  issuance normally takes a few seconds after the first claim.
* The CA's rate limits apply (for Let's Encrypt, notably a limit on
  certificates per registered domain per week), so avoid churning through
  many names. Use `--acme-directory` with a staging directory while
  experimenting.

Port 80 serves only `/.well-known/acme-challenge/...` and otherwise redirects
to HTTPS.

### Your own certificate

```sh
warren relay --domain relay.example.com --cert fullchain.pem --key privkey.pem
```

The certificate must cover the relay domain and every published name, which
in practice means a wildcard (`*.relay.example.com` plus
`relay.example.com`). The same certificate is served for every name.

### Self-signed (testing)

```sh
warren relay --domain relay.test --self-signed --listen 127.0.0.1:8443
# warren relay listening on 127.0.0.1:8443 for relay.test
# self-signed certificate; nodes join with --insecure-relay-cert-sha256 5e0c...
```

The certificate is generated once and kept in the state directory, so the pin
survives restarts. Nodes pin it at enrollment:

```sh
warren join CODE --relay https://relay.test:8443 --insecure-relay-cert-sha256 5e0c...
```

`warren relay info` prints the pin again.

## Administration

All admin commands run on the relay host and operate on the state directory
(`--state`, same default as the relay). They work while the relay is running;
the relay picks changes up within about a second.

```sh
warren relay invite [--name NAME]   # one-time code: 10 characters, 10 minutes, single use
warren relay nodes                  # enrolled nodes, fingerprints, revoked state
warren relay revoke NAME            # disconnect NAME now and refuse it from now on
warren relay domain add HOST NAME   # custom domain for a published name
warren relay info                   # counts and the self-signed pin
```

Revoking a node disconnects it at once (also a connection it is making at
that moment) and releases the names it published; a revoked node can never
claim names again. To replace a machine's keys (e.g. a reinstall):

1. on the relay host: `warren relay revoke NAME`, then
   `warren relay invite --name NAME`;
2. on the machine: `warren down` (the running daemon loaded the old keys and
   would keep using them, so `join` refuses to run while it is up), then
   `warren join --force CODE --relay https://relay.example.com`, then start it
   again with `warren up`, or `warren install` if it runs at login.

Its peers will then refuse the new key until they check the new fingerprint
(`warren status` on the machine shows it) and run
`warren trust NAME --expect FINGERPRINT`.

Enrollment codes are stored only as SHA-256 hashes. An IP address that fails 5
enrollment attempts within 10 minutes is refused until the window passes.

## Running as a service (systemd)

```ini
# /etc/systemd/system/warren-relay.service
[Unit]
Description=warren relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/warren relay --domain relay.example.com --acme you@example.com --state /var/lib/warren
Restart=always
RestartSec=2
DynamicUser=yes
StateDirectory=warren
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now warren-relay
sudo warren relay invite --state /var/lib/warren     # admin commands use the same directory
```

(With `DynamicUser=yes` the state directory is `/var/lib/private/warren`,
reachable through the `/var/lib/warren` symlink.)

## Firewall

Allow inbound TCP 443 (and 80 with `--acme`). Nothing else is needed: nodes
only ever connect out to the relay.

## State and backups

The state directory holds `relay.sqlite3` (enrolled nodes and their public
keys, invite hashes, published names, custom domains) and certificates.
Losing it means re-enrolling every machine. Back it up while the relay runs
with `sqlite3 relay.sqlite3 ".backup /path/backup.sqlite3"`. The files contain
no private keys of your machines; the TLS keys in it are private to the relay
and are `0600`.

## Limits enforced by the relay

| limit | value |
|---|---|
| concurrent streams per node | 1024 |
| stream opens per node | 64 per second |
| WebSocket message (one frame) | 65 542 bytes |
| per-stream window | 256 KiB per direction |
| stream data queued toward a node | 32 MiB (senders feeding it wait; no progress for 20 s disconnects the node) |
| other frames queued toward a node | 64 MiB |
| public TLS handshake + request head | 10 s |
| public idle connection | 5 min |
| public request head | 32 KiB |
| relay connections (any kind) | 16384 total, 256 per client IP |
| enrollment failures | 5 per IP per 10 minutes |
