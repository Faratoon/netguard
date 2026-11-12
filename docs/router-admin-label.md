# Router admin label (captured from `router1.jpg`)

Data read from the sticker on the bottom of the router:

| Field | Value |
|---|---|
| Brand | TELUS |
| Model | Wi-Fi Modem **T3200M** |
| Admin page | **http://192.168.1.254** |
| Admin user | `admin` |
| Admin password | `a5aa8zw2` |
| Wi-Fi SSID | `TELUS9630` |
| Wi-Fi password | `crdfy4f8h` |
| Serial number | `GTBA706309630` |
| MAC address | `10785BD435A1` |

> Read from the label photo at 2x zoom — the admin password is `a5aa8zw2`
> (8 characters, no digits swapped) and the Wi-Fi password is `crdfy4f8h`.

## How NetGuard uses this

The T3200M is an ISP modem: it has **no SSH**, so NetGuard talks to it through
its own web admin interface (`router.vendor: web`). NetGuard logs in with the
admin credentials, reads the status/device pages and extracts the client list
(MAC / IP / hostname).

The device MAC `10:78:5B:D4:35:A1` belongs to the router itself and is shown in
the admin info panel.

### Login note

The login page looks like it posts to `login.cgi`, but the firmware nests the
login form inside another `<form>` tag, so the browser really submits
`document.forms[0]` - no `method`, no `action` - which means a **GET request
to `/`** carrying the RSA-encrypted password. NetGuard implements exactly that
(including the RSA PKCS#1 v1.5 + base64 encryption the firmware uses).

Current admin credentials: user `admin`, password `Faratoon34#` - the login
works and NetGuard reads the authenticated pages.

### Write access is ISP-locked

The three parental-control pages exist and NetGuard drives them
(`netguard/services/telus.py`):

* Website Blocking -> `urlfilter.cmd` (`action=set_url`)
* Services Blocking -> `serv_block.cmd` (`rules=<ip>/<mask>|`, `command=add`)
* Scheduling Access -> `detail_access.tod` (`action=add`, `mac`, `days`, times)

However the modem answers every write with its generic *Thank you* page and
**stores nothing** (`allRule` / `rules` stay empty), so the TELUS firmware
rejects configuration changes made through the admin GUI. That is why NetGuard
enforces the filtering with its own **DNS filter server** instead - see
[docs/dns-filter-setup.md](dns-filter-setup.md).

## Safety

* The admin password above is the factory default — change it in the router's
  admin page and update `config.yaml` accordingly.
* `config.yaml` holds these credentials and is **not** committed to git
  (see `.gitignore`); only `config.example.yaml` is tracked.
* `router.dry_run: true` (the default) means NetGuard never modifies the
  router — it only shows you the exact commands it would run.
