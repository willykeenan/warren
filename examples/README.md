# Examples

The files used by [docs/production-relay.md](../docs/production-relay.md):
a relay on a small Ubuntu server behind nginx, with a certificate from
certbot, daily backups and a health check. Replace `relay.example.com`,
`203.0.113.10` and the published name `app` before installing them.

| file | goes to | step |
|---|---|---|
| `nginx/warren-http.conf` | `/etc/nginx/sites-available/warren-http` | 4 |
| `systemd/warren-relay.service` | `/etc/systemd/system/` | 5 |
| `nginx/warren-https.conf` | `/etc/nginx/sites-available/warren-https` | 6 |
| `scripts/warren-cert-renew` | `/etc/letsencrypt/renewal-hooks/deploy/warren-cert-renew` | 6 |
| `scripts/warren-backup` | `/usr/local/sbin/warren-backup` | 8 |
| `systemd/warren-backup.service`, `systemd/warren-backup.timer` | `/etc/systemd/system/` | 8 |
| `scripts/warren-health.py` | `~/.local/bin/` on another machine | 9 |
| `systemd/warren-health.service`, `systemd/warren-health.timer` | `~/.config/systemd/user/` on that machine | 9 |
