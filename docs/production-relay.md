# Running a relay in production

This is the setup behind the *Field report* in the README: one small Ubuntu
server running the relay as a locked, non-root service behind nginx, a
certificate from certbot that renews itself, a daily backup copied off the
server, and a health check that writes one JSON line every few minutes. Every
file it uses is in [`examples/`](../examples); replace `relay.example.com`,
`203.0.113.10`, `app` and `apphost` with your own names.

```
 browsers ───https──►  nginx :443  (certificate from certbot)
                         ├─ /v1/node, /healthz ─►  warren relay on 127.0.0.1:8443  (user warren)
                         └─ every other path   ─►  published name "app"  (same relay)
                                                        ▲
 apphost ───outbound wss to /v1/node────────────────────┘   warren publish 3000 --name app
```

Why this shape rather than the relay alone on port 443 (the README's quick
start):

* **One DNS record, no wildcard.** The published service lives at the
  relay's own name, `https://relay.example.com/`.
* **certbot handles the certificate.** warren's built-in ACME client has not
  yet been run against a live CA; certbot has.
* **The relay holds no privileges.** It listens on loopback only, runs as a
  user that cannot log in, and keeps no capabilities.

It has costs too, listed in *What the gateway changes* below. Read that
section before you rely on per-address limits or `publish --allow`.

## What you need

* A small Ubuntu LTS server with a public IPv4 address. The field report's
  relay has 1 GB of RAM.
* One DNS record: `relay.example.com. A 203.0.113.10`.
* SSH access to the server with a key.
* The machine whose service you publish (macOS or Linux), here `apphost`
  with a web server on port 3000.
* Somewhere else to keep backups and run the health check. The publishing
  machine will do.

## 1. Harden the server

Keep a second SSH session open until a fresh login works with the new
settings.

```sh
sudo tee /etc/ssh/sshd_config.d/00-key-only.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PermitEmptyPasswords no
EOF
sudo sshd -t && sudo systemctl reload ssh
```

Security updates every day, without automatic reboots:

```sh
sudo apt-get update && sudo apt-get install -y unattended-upgrades
sudo tee /etc/apt/apt.conf.d/52security-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
sudo systemctl enable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer
```

Firewall: SSH, and 80 and 443 for nginx. Nothing else; nodes only ever
connect out.

```sh
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 2. The service user

A system user that cannot log in, owning only the state directory:

```sh
sudo useradd --system --home-dir /var/lib/warren --create-home --shell /usr/sbin/nologin warren
sudo passwd -l warren
sudo install -d -m 700 -o warren -g warren /var/lib/warren
```

Run relay administration commands as this user, so every file in the state
directory stays its own:

```sh
sudo -u warren warren relay nodes --state /var/lib/warren
```

## 3. The binary

Build it on the server (Rust 1.88 or newer, as your normal user):

```sh
sudo apt-get install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/willykeenan/warren && cd warren
cargo build --release --locked -j 1
sudo install -m 755 target/release/warren /usr/local/bin/warren
warren --version
```

`-j 1` keeps a 1 GB server from running out of memory; the build then takes
about ten minutes. You can instead build on another x86_64 Linux machine, or
take the `x86_64-unknown-linux-gnu` binary from the releases page.

## 4. Port 80 and the certificate

Make sure the name already points at this server and nowhere else:

```sh
dig +short relay.example.com        # 203.0.113.10, nothing more
```

Serve ACME challenges on port 80
([`examples/nginx/warren-http.conf`](../examples/nginx/warren-http.conf)):

```sh
sudo apt-get install -y nginx certbot
sudo rm -f /etc/nginx/sites-enabled/default
sudo install -d -m 755 /var/lib/warren-acme
sudo install -m 644 examples/nginx/warren-http.conf /etc/nginx/sites-available/warren-http
sudo ln -s /etc/nginx/sites-available/warren-http /etc/nginx/sites-enabled/warren-http
sudo nginx -t && sudo systemctl enable --now nginx && sudo systemctl reload nginx
```

Try against the staging CA first (`--dry-run` saves nothing), then get the
real certificate. `--email` gets you the CA's expiry warnings; use
`--register-unsafely-without-email` instead if you rely on the health check
for that.

```sh
sudo certbot certonly --webroot -w /var/lib/warren-acme -d relay.example.com \
    --email you@example.com --agree-tos --non-interactive --dry-run
sudo certbot certonly --webroot -w /var/lib/warren-acme -d relay.example.com \
    --email you@example.com --agree-tos --non-interactive
```

The relay cannot read `/etc/letsencrypt`, so give it its own copy:

```sh
sudo install -d -m 700 -o warren -g warren /var/lib/warren/certs/live
sudo install -m 600 -o warren -g warren /etc/letsencrypt/live/relay.example.com/fullchain.pem /var/lib/warren/certs/live/
sudo install -m 600 -o warren -g warren /etc/letsencrypt/live/relay.example.com/privkey.pem /var/lib/warren/certs/live/
```

Step 6 sets up a hook that repeats this copy after every renewal.

## 5. The relay service

[`examples/systemd/warren-relay.service`](../examples/systemd/warren-relay.service)
runs the relay as `warren`, listening on `127.0.0.1:8443` only, with the
certificate from step 4. It restarts on failure, is sandboxed
(`ProtectSystem=strict`, writable state directory only, no capabilities), and
allows the open files the relay needs.

```sh
sudo install -m 644 examples/systemd/warren-relay.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/warren-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now warren-relay
curl --resolve relay.example.com:8443:127.0.0.1 https://relay.example.com:8443/healthz    # ok
```

To see the restart work, kill the process and look again:

```sh
pid=$(systemctl show -p MainPID --value warren-relay)
sudo kill -KILL "$pid"; sleep 7
systemctl show -p MainPID -p NRestarts warren-relay      # a new PID, NRestarts=1
```

## 6. The HTTPS gateway and renewal

[`examples/nginx/warren-https.conf`](../examples/nginx/warren-https.conf)
sends `/v1/node` and `/healthz` to the relay and every other path to the
published name `app`. The hop to the relay is TLS as well, checked against the
same public certificate. It also limits each client by its own address; see
*What the gateway changes* for why.

```sh
sudo install -m 644 examples/nginx/warren-https.conf /etc/nginx/sites-available/warren-https
sudo ln -s /etc/nginx/sites-available/warren-https /etc/nginx/sites-enabled/warren-https
sudo nginx -t && sudo systemctl reload nginx
curl https://relay.example.com/healthz        # ok, from anywhere
```

Check that a WebSocket upgrade reaches the relay. Expect
`HTTP/1.1 101 Switching Protocols`; curl then waits until `--max-time`.

```sh
curl -si --http1.1 --max-time 5 https://relay.example.com/v1/node \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' | head -1
```

A `404` here means the `Upgrade` and `Connection` headers were lost on the
way. nginx inherits `proxy_set_header` from the server block only when a
location sets none. Each location in the example sets `Host`, so the example
repeats the upgrade pair in every location. The field report's gateway first
went up without them, and enrollment failed with exactly this 404.

Renewal: the certbot package's `certbot.timer` runs twice a day and renews
30 days before expiry. The deploy hook
[`examples/scripts/warren-cert-renew`](../examples/scripts/warren-cert-renew)
copies the new certificate to the relay, restarts it and reloads nginx.
Nodes reconnect within seconds; open published connections are dropped once
every couple of months.

```sh
sudo install -m 755 examples/scripts/warren-cert-renew /etc/letsencrypt/renewal-hooks/deploy/warren-cert-renew
sudo systemctl enable --now certbot.timer
sudo certbot renew --dry-run
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/relay.example.com /etc/letsencrypt/renewal-hooks/deploy/warren-cert-renew
```

The dry run proves renewal works but skips deploy hooks, so the last line runs
the hook once by hand.

## 7. Enroll the machine and publish

On the server, one code per machine (10 minutes, single use):

```sh
sudo -u warren warren relay invite --name apphost --state /var/lib/warren
```

On `apphost`:

```sh
warren join CODE --relay https://relay.example.com --name apphost
warren install                     # start `warren up` at login
warren publish 3000 --name app     # what the gateway's `location /` serves
warren status
```

`https://relay.example.com/` now reaches port 3000 on `apphost`. Names are
lowercase letters, digits and hyphens. `warren publish` still prints
`https://app.relay.example.com/`, the address the relay itself would use;
without a wildcard record, this gateway's address is the one that works.

Nodes connect to port 443 through nginx while the relay listens on 8443.
That is fine: their login signature covers the host name, which is the
relay's `--domain` on both sides, not the port.

Your app sees `Host: app.relay.example.com` (and the same
`X-Forwarded-Host`), while browsers use `https://relay.example.com/`. If it
builds absolute URLs, or redirects requests for host names it does not know,
set its public URL to `https://relay.example.com` explicitly.

## 8. Backups

The state directory holds the enrolled machines' public keys and names, the
published names and the relay's certificate. Losing it means enrolling every
machine again.
[`examples/scripts/warren-backup`](../examples/scripts/warren-backup)
copies it while the relay runs, takes the database through SQLite's online
backup API, checks the copy's integrity, and writes a private
`warren-YYYYMMDDTHHMMSSZ.tar.gz` plus a `latest.tar.gz` link. The timer runs
it daily at 06:15 UTC.

```sh
sudo install -m 755 examples/scripts/warren-backup /usr/local/sbin/warren-backup
sudo install -m 644 examples/systemd/warren-backup.service examples/systemd/warren-backup.timer /etc/systemd/system/
sudo install -d -m 700 /var/backups/warren
sudo systemctl daemon-reload
sudo systemctl enable --now warren-backup.timer
sudo systemctl start warren-backup.service
sudo journalctl -u warren-backup -n 3 --no-pager       # BACKUP_OK warren-....tar.gz bytes=...
```

Archives are small (a few KB a day) and kept forever unless you set
`WARREN_BACKUP_KEEP_DAYS` in the service.

**Copy them off the server.** A backup on the same disk does not survive the
server. From another machine, after 06:20 UTC each day:

```sh
mkdir -p ~/warren-backups && chmod 700 ~/warren-backups
scp root@203.0.113.10:/var/backups/warren/latest.tar.gz ~/warren-backups/warren-$(date -u +%Y%m%d).tar.gz
```

or as a crontab line (`%` must be escaped there):

```
30 7 * * * scp -q root@203.0.113.10:/var/backups/warren/latest.tar.gz "$HOME/warren-backups/warren-$(date -u +\%Y\%m\%d).tar.gz"
```

Check a copy: the checksums match and the database is intact.

```sh
ssh root@203.0.113.10 'sha256sum /var/backups/warren/latest.tar.gz'
sha256sum ~/warren-backups/warren-YYYYMMDD.tar.gz      # macOS: shasum -a 256
check=$(mktemp -d) && tar -xzf ~/warren-backups/warren-YYYYMMDD.tar.gz -C "$check"
sqlite3 "$check/warren/relay.sqlite3" 'PRAGMA integrity_check'    # ok
rm -rf "$check"
```

Every archive holds the relay's TLS private key. Keep the copies private,
and delete the unpacked check copy, as above.

To restore on the same server (or on a new one after steps 1 to 6, with the
DNS record pointed at it):

```sh
sudo systemctl stop warren-relay
sudo mv /var/lib/warren /var/lib/warren.before-restore
sudo tar -xzf warren-YYYYMMDD.tar.gz -C /var/lib
sudo chown -R warren:warren /var/lib/warren && sudo chmod 700 /var/lib/warren
sudo systemctl start warren-relay
```

Enrolled machines reconnect with their existing keys. In the field report a
backup has been unpacked and checked on another machine; a full restore onto
a fresh server has not been rehearsed yet.

## 9. Health check

[`examples/scripts/warren-health.py`](../examples/scripts/warren-health.py)
needs only Python 3.8+. Run it from a machine other than the relay, so it sees
what clients see and still reports when the relay host is down. Each run
appends one line to a JSONL file, prints it, and exits `0` when healthy, `1`
when not (`2` for a usage error).

```sh
warren-health.py --relay https://relay.example.com \
    --publish-url https://relay.example.com/ --expect-text 'Sign in' \
    --expect-ip 203.0.113.10 --out ~/.local/state/warren/health.jsonl
```

| flag | checks |
|---|---|
| `--relay URL` | `URL/healthz` answers `200` with `ok` over verified TLS (required) |
| `--publish-url URL` | a page of the published service; redirects are **not** followed |
| `--publish-status N...` | accepted status codes for that page (default `200`) |
| `--expect-text TEXT` | the page contains `TEXT` (case-insensitive) |
| `--expect-ip ADDR` | the answer comes from the relay's address and no other server |
| `--min-cert-days N` | the certificate has at least `N` days left (default 14; certbot renews at 30) |
| `--node` | also asks the local node: `warren --json status` (honours `WARREN_HOME`; `--warren PATH` for the binary) |
| `--publish-name NAME` | with `--node`: that name is published by this machine |
| `--compare-url URL` | another route to the same service, measured but never judged |

`--expect-ip` and not following redirects matter. A redirect to another
route, or another server answering for the name, would otherwise pass
without warren carrying anything. The field report's first health check
followed redirects and could have passed that way.

One line (wrapped here):

```json
{"timestamp":"2026-10-06T01:00:00.312518+00:00","healthy":true,"problems":[],
 "relay":{"url":"https://relay.example.com/healthz","http_status":200,"latency_ms":145.98,
  "tls_verified":true,"remote_ip":"203.0.113.10","expected_ip":true,"content_ok":true,"error":null},
 "certificate":{"verified":true,"endpoint_ip":"203.0.113.10",
  "expires_at":"2027-01-04T00:00:00+00:00","days_remaining":89.96},
 "publish":{"url":"https://relay.example.com/","http_status":200,"latency_ms":106.36,
  "tls_verified":true,"remote_ip":"203.0.113.10","expected_ip":true,"content_ok":true,"error":null},
 "node":{"state":"connected","latency_ms":15.07,"connects":2,"publish_registered":true,"error":null},
 "compare":null,"check_ms":588.27}
```

| field | meaning |
|---|---|
| `timestamp` | when the check started, UTC |
| `healthy` | `true` exactly when `problems` is empty |
| `problems` | short codes, listed below |
| `relay`, `publish`, `compare` | one request each: `http_status` (`0`: no answer), `latency_ms` (connect, TLS and response), `tls_verified`, `remote_ip`, `expected_ip` (`null` without `--expect-ip`), `content_ok` (`null` when not checked), `error` |
| `certificate` | from the relay request: `verified`, `endpoint_ip`, `expires_at`, `days_remaining` |
| `node` | with `--node`: `state`, `latency_ms` to the relay, `connects` since the daemon started (more than 1 means it reconnected), `publish_registered`, `error` |
| `check_ms` | duration of the whole check |

Problem codes: `relay_unreachable`, `relay_tls`, `relay_status`,
`relay_content`, `relay_wrong_server`, `certificate_expiring`, the same five
with `publish_`, `node_not_connected` and `node_publish_missing`.

Every five minutes on Linux, as your user, with
[`examples/systemd/warren-health.service`](../examples/systemd/warren-health.service)
and [`.timer`](../examples/systemd/warren-health.timer):

```sh
install -D -m 755 examples/scripts/warren-health.py ~/.local/bin/warren-health.py
install -D -m 644 examples/systemd/warren-health.service examples/systemd/warren-health.timer -t ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now warren-health.timer
loginctl enable-linger "$USER"      # keep it running when nobody is logged in
```

With cron instead: `*/5 * * * * python3 $HOME/.local/bin/warren-health.py --relay https://relay.example.com ... >/dev/null`.
On macOS, a launchd agent with `StartInterval` 300 does the same; the field
report runs it that way.

Summarise a log (sample counts and p50/p95/max latency per route):

```sh
warren-health.py --summary ~/.local/state/warren/health.jsonl
```

These are samples every five minutes, not proof of continuous uptime.

## 10. Updating warren

Take a backup, install the new binary and restart. Nodes reconnect by
themselves.

```sh
sudo systemctl start warren-backup.service
sudo install -m 755 target/release/warren /usr/local/bin/warren
sudo systemctl restart warren-relay
curl https://relay.example.com/healthz
```

## What the gateway changes

Behind nginx, the relay sees every connection coming from `127.0.0.1`. In
warren 0.1 that means:

* **Per-address limits become one shared limit.** The 256-connections-per-
  address cap now covers all clients and nodes together. Each node holds one
  connection, and each open browser connection to the published app holds
  another. The limit of 5 failed enrollments per address per 10 minutes is
  shared too, so someone guessing codes can delay your next `warren join` by
  up to ten minutes. The example gateway therefore limits each client in
  nginx (`limit_conn`/`limit_req` by client address): 64 requests in progress
  per client, so no single client can take all 256 connections, and 6
  connection attempts to `/v1/node` followed by one every 10 seconds, which
  slows code guessing. nginx cannot tell a failed enrollment from a good one,
  so one client can still cause the shared ten-minute wait. If a CDN or
  another proxy sits in front of nginx, give nginx its addresses with
  `set_real_ip_from`, or all of that proxy's clients share one limit.
* **`warren publish --allow` cannot tell clients apart.** Every request comes
  from `127.0.0.1`, so an allowlist containing it admits everyone. Restrict
  access in nginx instead (`allow`/`deny` in `location /`).
* **The app sees `X-Forwarded-For: 127.0.0.1`**, not the client's address.
* **One published name per public name.** For another, add a DNS record, a
  certificate and a server block like `location /` with that name's `Host`.

If you do not need a single DNS name or certbot, running the relay on port
443 itself (see [relay.md](relay.md)) avoids all four.

## Stop and remove everything

### Stop (reversible)

```sh
# on the monitoring machine
systemctl --user disable --now warren-health.timer
# on apphost (unpublish while the daemon still runs)
warren unpublish app
warren down
# on the server
sudo systemctl disable --now warren-backup.timer
sudo rm /etc/nginx/sites-enabled/warren-https && sudo systemctl reload nginx
sudo systemctl stop warren-relay
```

To start again, reverse the steps: link `warren-https` again and reload
nginx, start `warren-relay`, enable the backup timer, run `warren up` (or
`warren install`) and `warren publish 3000 --name app` on `apphost`, and
enable the health timer.

### Remove

Run these in order. Take a last backup first if you may want the state
(step 8).

1. Every enrolled machine. Remove warren from the machine, then revoke it on
   the server (revoking works whether the relay runs or not):

   ```sh
   # on apphost
   warren unpublish app    # needs the daemon running; skip it if you did it under Stop
   warren uninstall
   rm -rf ~/.warren        # its keys; or your WARREN_HOME
   # on the server, for each machine
   sudo -u warren warren relay revoke apphost --state /var/lib/warren
   ```

2. The server. Revoke the certificate rather than only deleting it: copies of
   its private key sit in every backup.

   ```sh
   sudo rm -f /etc/nginx/sites-enabled/warren-http /etc/nginx/sites-enabled/warren-https \
              /etc/nginx/sites-available/warren-http /etc/nginx/sites-available/warren-https \
              /etc/letsencrypt/renewal-hooks/deploy/warren-cert-renew
   sudo systemctl disable --now nginx certbot.timer    # only if nothing else here uses them
   sudo certbot revoke --cert-name relay.example.com --reason cessationofoperation \
       --delete-after-revoke --non-interactive
   sudo systemctl disable --now warren-relay.service warren-backup.timer
   sudo systemctl stop warren-backup.service
   sudo rm -f /etc/systemd/system/warren-relay.service /etc/systemd/system/warren-backup.service \
              /etc/systemd/system/warren-backup.timer /usr/local/bin/warren /usr/local/sbin/warren-backup
   sudo systemctl daemon-reload
   sudo userdel warren
   sudo rm -rf /var/lib/warren /var/backups/warren /var/lib/warren-acme
   sudo ufw delete allow 80/tcp
   sudo ufw delete allow 443/tcp
   ```

   Keep the SSH hardening and automatic security updates. Removing warren is
   no reason to weaken the server.

3. DNS: delete the `relay.example.com` record at your DNS provider, then
   check that `dig +short relay.example.com` prints nothing.

4. The monitoring and backup machine:

   ```sh
   systemctl --user disable --now warren-health.timer
   rm -f ~/.config/systemd/user/warren-health.service ~/.config/systemd/user/warren-health.timer \
         ~/.local/bin/warren-health.py
   systemctl --user daemon-reload
   ```

   `~/.local/state/warren/health.jsonl` is history; delete it if you don't
   want it. Delete `~/warren-backups` (and its crontab line) unless you keep
   the state on purpose. It holds the relay's private key and the list of
   your machines.

5. If the server existed only for this, delete it at your provider.
