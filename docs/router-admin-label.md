# Router admin label (captured from `router1.jpg`)

Data read from the sticker on the bottom of the router:

| Field | Value |
|---|---|
| Brand | TELUS |
| Model | Wi-Fi Modem **T3200M** |
| Admin page | **http://192.168.1.254** |
| Admin user | `admin` |
| Admin password | `a5aa8z2w2` |
| Wi-Fi SSID | `TELUS9630` |
| Wi-Fi password | `crfd6y4f8h` |
| Serial number | `GT8A706309630` |
| MAC address | `10785BD435A1` |

## How NetGuard uses this

The T3200M is an ISP modem: it has **no SSH**, so NetGuard talks to it through
its own web admin interface (`router.vendor: web`). NetGuard logs in with the
admin credentials, reads the status/device pages and extracts the client list
(MAC / IP / hostname).

The device MAC `10:78:5B:D4:35:A1` belongs to the router itself and is shown in
the admin info panel.

## Safety

* The admin password above is the factory default — change it in the router's
  admin page and update `config.yaml` accordingly.
* `config.yaml` holds these credentials and is **not** committed to git
  (see `.gitignore`); only `config.example.yaml` is tracked.
* `router.dry_run: true` (the default) means NetGuard never modifies the
  router — it only shows you the exact commands it would run.
