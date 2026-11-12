# NetGuard

Open-source **router & network administration, monitoring and parental-control dashboard**.

NetGuard talks to your router (OpenWrt / LuCI over SSH, or any generic SSH router),
collects the admin data you would normally read in the router web UI, and puts it
into one dashboard — plus the controls a parent actually needs: content filtering,
per-device rules, curfews and network speed/load monitoring.

```
┌──────────────┐   SSH/ubus    ┌───────────┐   REST   ┌────────────────────────┐
│ OpenWrt /    │◄──────────────►│  NetGuard │◄────────►│ Web dashboard / API    │
│ your router  │               │  (Python) │          │ devices, rules, speed │
└──────────────┘               └───────────┘          └────────────────────────┘
```

## Features

| Area | What you get |
|---|---|
| **Device inventory** | Every client on the LAN (MAC, IP, hostname, vendor/OUI, device type), live scan and per-device actions |
| **Router admin data** | Model, firmware, uptime, CPU/memory/load, WAN IP + gateway, DNS servers, DHCP pool, Wi-Fi radios, raw `ubus` payload |
| **Speed & load** | Speed test (download/upload/latency), ping, traceroute, DNS lookup, subnet scan, port scan, per-interface counters, traffic history chart |
| **Parental controls** | DNS-level content filtering (adult/social/gaming/risky categories), per-device rules for domain / app / IP / MAC, allow-rules that override blocks |
| **Curfews** | Time windows per device, e.g. 21:00–07:00 safe mode or full internet cut-off |
| **App & mic blocking** | Block apps that use the microphone/camera (Discord, TikTok, Snapchat, Zoom…) by blocking their domains — the app stops working on that device |
| **Image management** | Upload device photos or router admin screenshots, capture what a blocked page looks like (Playwright), auto-generated SVG network topology map |
| **Audit log** | Every blocked request is logged with device, target, category and reason |
| **Safe mode** | One toggle per device that blocks the risky categories without touching the router config |

## Quick start (demo mode, no router needed)

```bash
git clone https://github.com/<your-user>/netguard.git
cd netguard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml        # config.yaml in the repo already uses the mock router
uvicorn netguard.main:app --host 0.0.0.0 --port 8080
```

Open <http://localhost:8080>. With `router.vendor: mock` you get a fully working
dashboard populated with fake devices — good for trying things out.

## Connect it to your real router

### TELUS T3200M (ISP modem, no SSH)

The T3200M only exposes its own web admin page, so NetGuard logs into it over
HTTP and scrapes the client list (`router.vendor: web`). Credentials come from
the label on the bottom of the router — see
[docs/router-admin-label.md](docs/router-admin-label.md).

```yaml
router:
  vendor: web
  host: 192.168.1.254
  user: admin
  password: <admin password from the label>
  dry_run: true
```

### OpenWrt / any router with SSH

```yaml
router:
  vendor: openwrt
  host: 192.168.1.1
  user: root
  key_file: ~/.ssh/id_ed25519     # or use `password:`
  dry_run: true                    # keep true while testing
```

1. Make sure SSH is enabled on the router and your key is in `~/.ssh/authorized_keys`.
2. Open the **Admin Data** tab, press *Refresh*. You should see the router model,
   firmware, WAN IP and memory usage.
3. Press **Scan devices** — the client list is merged into the local inventory.
4. When you are happy with the rules, set `dry_run: false` and use
   *Push to router* (or the `POST /api/controls/apply` endpoint) to write the
   dnsmasq blocklist and the per-device firewall rules.

### What "Push to router" does

* **Content filter** — writes a dnsmasq include file
  (`address=/blocked-domain/0.0.0.0`) and reloads dnsmasq, so blocked domains
  resolve to `0.0.0.0` for everybody.
* **Blocked device** — an `iptables` rule dropping all traffic from that MAC.
* **Quarantined device** — an `iptables` `REJECT` (no internet at all).
* **Unblocked device** — removes the NetGuard drop rule again.

Every command is shown in the UI before it is executed, so you always know what
touches the router.

## API

Interactive docs: <http://localhost:8080/docs>

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/devices` | device inventory (add `?sync=false` to skip the router scan) |
| PATCH | `/api/devices/{id}` | rename a device, toggle block / safe mode / quarantine |
| GET | `/api/admin/info` | everything from the router admin page in one payload |
| POST | `/api/admin/snapshot` | store a timestamped snapshot of the router state |
| GET | `/api/network/status` | router + local interface counters |
| POST | `/api/network/collect` | take a traffic/load sample now |
| GET | `/api/network/traffic?hours=24` | traffic history |
| POST | `/api/network/speedtest` | download/upload/latency measurement |
| POST | `/api/network/ping` `/traceroute` `/dns` `/scan` `/portscan` | diagnostics |
| GET | `/api/controls/blocklist` | blocked domains |
| POST | `/api/controls/blocklist` | block a domain |
| POST | `/api/controls/policies` | add a rule (domain / app / ip / mac, block or allow) |
| POST | `/api/controls/curfews` | add a time window for a device |
| POST | `/api/controls/check` | "would this be blocked?" test |
| POST | `/api/controls/apply` | preview (`apply:false`) or push rules to the router |
| GET | `/api/media/topology.svg` | generated network map |
| POST | `/api/media/upload` | store an image (device photo, admin screenshot…) |

Set `api_token` in the config to protect the API — clients then send the header
`X-NetGuard-Token: <token>`.

## Docker

```bash
docker compose up -d
```

The compose file mounts `config.yaml` and the `data/` folder (database + images).

## Configuration

All values live in `config.yaml` (see `config.example.yaml`). Everything can also
be set through environment variables:

| Variable | Meaning |
|---|---|
| `NETGUARD_ROUTER_VENDOR` | `openwrt`, `generic-ssh` or `mock` |
| `NETGUARD_ROUTER_HOST` / `_USER` / `_PASSWORD` / `_KEY` | router connection |
| `NETGUARD_DRY_RUN` | `true` = never modify the router |
| `NETGUARD_API_TOKEN` | API token |
| `NETGUARD_DATA_DIR` | where the SQLite DB and images are stored |
| `NETGUARD_DEMO` | `true` = use the built-in mock router |

## Development

```bash
source .venv/bin/activate
pip install -r requirements.txt
pytest -q            # 14 tests
uvicorn netguard.main:app --reload
```

Layout:

```
netguard/
├── config.py            # YAML + env configuration
├── db.py                # SQLAlchemy models (devices, policies, blocklist, …)
├── state.py             # shared state, device merging, vendor detection
├── main.py              # FastAPI app, background sampler
├── api/                 # devices, controls, network, admin, media
├── services/
│   ├── router.py        # OpenWrt/SSH + mock router client
│   ├── rules.py         # domain matching, curfew logic, presets
│   ├── firewall.py      # dnsmasq + iptables command generation
│   ├── nettools.py      # ping, traceroute, speedtest, scans
│   └── media.py         # uploads, thumbnails, SVG topology
└── static/              # dashboard (vanilla HTML/CSS/JS)
```

## Safety notes

* NetGuard only talks to **your own** router and only enforces rules on your own
  network. Keep `dry_run: true` until the generated commands look right.
* Blocking by DNS is easy to bypass for a technical user; combine it with the
  firewall rules and the device quarantine for a stronger guarantee.
* The optional Playwright screenshot feature needs `pip install playwright &&
  playwright install chromium`.

## License

MIT — see [LICENSE](LICENSE).
