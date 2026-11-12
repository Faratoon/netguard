# Setting up the DNS filter (blocking adult sites and more)

NetGuard runs its own DNS server. Any device that uses it as its resolver gets
blocked domains resolved to `0.0.0.0` while everything else works normally.

On the Windows PC (which is on the same LAN as the router) the filter runs on
**192.168.1.74:53** and forwards to the ISP resolvers
`75.153.171.67` / `75.153.171.124` (plus `1.1.1.1` as a fallback).

## Point a device at it

**Android (Pixel 7, Samsung, …)**
1. Settings → Wi-Fi → long-press your network → *Modify network*
2. *Advanced* → IP settings → **Static**
3. DNS 1 = `192.168.1.74` (DNS 2 can stay empty)
4. *Private DNS* → **Off** (otherwise Android bypasses your DNS)

**iPhone / iPad**
1. Settings → Wi-Fi → tap the ⓘ next to your network
2. *Configure DNS* → **Manual** → delete the default entries → add `192.168.1.74`
3. Save

**Windows / laptop**
Settings → Network & internet → Wi-Fi → *DNS server assignment* → **Manual** →
`192.168.1.74`, and turn off "DNS over HTTPS".

**Whole network at once**
Set the DHCP DNS server of the LAN to `192.168.1.74` in the router
(Advanced Setup → DHCP). The TELUS firmware accepts the command but does not
store it (ISP lock), so per-device is the reliable route today.

## Verify

```bash
# from any machine on the LAN
nslookup pornhub.com 192.168.1.74     # -> 0.0.0.0
nslookup wikipedia.org 192.168.1.74   # -> a real address
```

Or use the dashboard: **Parental Controls → DNS filter → Test a lookup**.

## What gets blocked

* Everything in the blocklist (start with **Import adult preset** → 16 domains)
* Every domain matching a blocked rule, per device or globally
* Safe mode on a device (blocks adult + social + gaming categories)
* Curfew windows (`safe_mode` or `block_internet`) while they are active
* Apps that use the microphone/camera (Discord, TikTok, Snapchat, Zoom…) when
  you add an *app* rule for them

Blocked lookups are written to the audit trail (**Parental Controls → events**)
with the device, the domain and the reason.

## Notes

* DNS filtering stops casual access. A determined user can bypass it with a
  VPN, a hardcoded DNS server or another browser — for stronger guarantees use
  the per-device *block* / *cut internet* switches as well (those need router
  write access, which the ISP firmware currently rejects).
* NetGuard never touches the router's configuration unless you press
  *Push to router* with `dry_run: false`.
