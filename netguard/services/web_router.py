"""HTTP admin scraper for ISP routers (TELUS T3200M / Sagemcom-Technicolor style).

The T3200M has no SSH. Its web UI (mini_httpd + a big inline JavaScript config
blob) exposes the full admin state on the home page:

* ``hostinfo``      -> connected clients: ``name/ip/mac/...`` separated by ``|``
* ``wanInfNames``   -> WAN interface, IP, gateway, DNS, uptime, router MAC
* ``devinfo``       -> model | firmware | bootloader | hardware
* ``gv_ssid``       -> Wi-Fi SSID, ``gv_wlAuthMode`` -> encryption
* ``dsl_dns1/2``    -> DNS servers, ``dsltime`` -> uptime, ``fwLevel`` -> firewall

The module therefore works without a successful login, and optionally logs in
(``login.cgi``) to fetch the deeper device pages when the admin password is
accepted.
"""
from __future__ import annotations

import base64
import html
import os
import re
from typing import Any

import httpx

from ..config import RouterConfig
from .router import BaseRouter, RouterDevice, RouterStatus

MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")
IP_RE = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")

#: public RSA key used by the router GUI to encrypt the admin password
DEFAULT_RSA_MODULUS = (
    "EDA017EBA532CD23754813203F4026C78EB9089FB7DA16ABBC5220C87BEC3B3C9684E8181AE8AE56C"
    "BAEE40BA5B2778A9BA4B59FF6C4FFFEB086E4BC288CC00E970C4CE0BEFAD7ED23FFD6D86F5B2B400E"
    "D11F20CCFF67D9DF6DA8620EE5CA20741265A5AF51AE2EF0B1D3834F3E90D5545D12CA67B629332F34"
    "9020C9A5789B01BA147870108FC436CEEB401DD0BEADA4E2F0DB6AB6D506E7D0AD1C947FCEF38346E8"
    "2F6D6048D2683494DE8E515243FD1C750C6E6195436BB6FA1F0E4BF86471AB30B34C2FCEEB1DAE8937"
    "C0B8B265AC1067FF6EC46402AA2853B8D69C157C3B08F165C1976E799801F29FBD18516AAAC3B94901"
    "284202DF1E941EB9FB86F"
)

EXTRA_PAGES = [
    "/devicelist.asp",
    "/devicelist.html",
    "/device_list.html",
    "/status.asp",
    "/home.html",
    "/network.html",
    "/index.html",
]


def rsa_encrypt_password(password: str, modulus_hex: str = DEFAULT_RSA_MODULUS) -> str:
    """Encrypt a password the same way the router GUI does (RSA PKCS#1 v1.5 + base64)."""
    n = int(modulus_hex, 16)
    e = 65537
    k = (n.bit_length() + 7) // 8
    message = password.encode()
    pad_len = k - len(message) - 3
    padding = bytearray()
    while len(padding) < pad_len:
        padding += bytes([b for b in os.urandom(128) if b != 0][: pad_len - len(padding)])
    block = b"\x00\x02" + bytes(padding) + b"\x00" + message
    cipher = pow(int.from_bytes(block, "big"), e, n)
    return base64.b64encode(cipher.to_bytes(k, "big")).decode()


def _js_value(text: str, name: str) -> str | None:
    """Read a JavaScript variable value such as ``var hostinfo = '...'``."""
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*(?:htmlDecodeStr\(\s*)?(['\"])(.*?)\1",
        text,
        re.S,
    )
    if not match:
        return None
    return html.unescape(match.group(2).replace("\\'", "'").replace('\\"', '"'))


class WebRouter(BaseRouter):
    """Scrapes the router's own web admin interface over HTTP."""

    def __init__(self, cfg: RouterConfig):
        super().__init__(cfg)
        self.base = f"http://{cfg.host}"
        self._client: httpx.Client | None = None
        self._html = ""
        self._extra_pages: list[str] = []
        self._logged_in = False

    # ---------------------------------------------------------------- http
    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base,
                timeout=self.cfg.timeout,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (NetGuard)"},
                verify=False,
            )
        return self._client

    def exec(self, command: str, timeout: int | None = None) -> str:
        """Fetch a page of the admin UI (command = path)."""
        response = self._http().get(command if command.startswith("/") else f"/{command}")
        response.raise_for_status()
        return response.text

    def refresh(self) -> None:
        """Download the home page (and, if logged in, the extra pages)."""
        client = self._http()
        self._html = client.get("/").text
        self._extra_pages = []
        if self._logged_in:
            for path in EXTRA_PAGES:
                try:
                    response = client.get(path)
                except Exception:
                    continue
                if response.status_code == 200 and response.text and "<html" in response.text.lower():
                    self._extra_pages.append(response.text)

    def login(self) -> bool:
        """Try to log in to the admin UI (needed for the deeper device pages)."""
        client = self._http()
        self.refresh()
        password = self.cfg.password or ""
        if not password:
            return False

        payload = {
            "sessionKey": _js_value(self._html, "sessionKey") or "0",
            "sessionId": str(int.from_bytes(os.urandom(3), "big") % 799999999 + 1),
            "inputUserName": self.cfg.user or "",
            "inputPassword": rsa_encrypt_password(password),
            "nothankyou": "1",
        }
        try:
            response = client.post("/login.cgi", data=payload)
        except Exception:
            return False
        self._logged_in = "msg=err" not in response.text
        if self._logged_in:
            self.refresh()
        return self._logged_in

    # ------------------------------------------------------------- status
    def status(self) -> RouterStatus:
        if not self._html:
            self.refresh()
        text = self._html
        st = RouterStatus(hostname=self.cfg.host)

        devinfo = _js_value(text, "devinfo")
        if devinfo:
            parts = devinfo.split("|")
            st.model = parts[0]
            st.firmware = parts[2] if len(parts) > 2 else "unknown"
            st.raw["device_info"] = parts

        wan = _js_value(text, "wanInfNames")
        if wan:
            st.raw["wan_interface"] = wan
            fields = wan.split(":")
            # ...:IPoE:0/<ip>/<mask>/<gateway>/.../Connected/<mac>/LLC/<dns>/...
            for field in fields:
                if "/" in field and re.match(r"^\d+\.\d+\.\d+\.\d+", field.split("/")[1] if len(field.split("/")) > 1 else ""):
                    parts = field.split("/")
                    if len(parts) >= 4:
                        st.wan_ip = parts[1]
                        st.wan_gateway = parts[3]
                if "," in field and re.search(r"\d+\.\d+\.\d+\.\d+", field):
                    st.dns_servers = [ip for ip in field.split(",") if IP_RE.fullmatch(ip)]
            if st.wan_ip is None:
                ips = [ip for ip in IP_RE.findall(wan) if not _is_private(ip)]
                st.wan_ip = ips[0] if ips else None
            mac = re.search(r"/([0-9a-f]{2}(?:-[0-9a-f]{2}){5})/", wan)
            if mac:
                st.raw["router_mac"] = mac.group(1).upper().replace("-", ":")

        st.dns_servers = st.dns_servers or [
            ip for ip in (_js_value(text, "dsl_dns1"), _js_value(text, "dsl_dns2")) if ip
        ]
        st.lan_ip = self.cfg.host
        uptime = _js_value(text, "dsltime")
        if uptime and uptime.isdigit():
            st.uptime_seconds = int(uptime)
        st.raw["ssid"] = _js_value(text, "gv_ssid")
        st.raw["ssid_5ghz"] = _js_value(text, "gv_ssid_5")
        st.raw["wifi_auth"] = _js_value(text, "gv_wlAuthMode")
        st.raw["firewall_level"] = _js_value(text, "fwLevel")
        st.raw["authenticated"] = self._logged_in
        st.raw["captured_at"] = None
        if st.raw["ssid"]:
            st.wireless = [{"radio": "radio0", "ssid": st.raw["ssid"], "up": True}]
        return st

    # ------------------------------------------------------------ clients
    def clients(self) -> list[RouterDevice]:
        if not self._html:
            self.refresh()
        text = self._html
        devices: list[RouterDevice] = []
        seen: set[str] = set()

        hostinfo = _js_value(text, "hostinfo") or ""
        for entry in hostinfo.split("|"):
            fields = entry.split("/")
            if len(fields) < 3:
                continue
            name, ip, mac = fields[0], fields[1], fields[2]
            mac = mac.upper().replace("-", ":")
            if not MAC_RE.fullmatch(mac) or mac in seen:
                continue
            seen.add(mac)
            device = RouterDevice(mac=mac, ip=ip, hostname=name, interface="wifi" if len(fields) > 3 else "lan")
            devices.append(device)

        # wired clients: mac/state/port
        wpinfo = _js_value(text, "wpclientinfo") or ""
        for entry in wpinfo.split("|"):
            fields = entry.split("/")
            if not fields:
                continue
            mac = fields[0].upper().replace("-", ":")
            if MAC_RE.fullmatch(mac) and mac not in seen:
                seen.add(mac)
                devices.append(RouterDevice(mac=mac, hostname="wired-client", interface="lan"))

        # fallback for other firmwares: scrape every MAC of the device pages
        for page in self._extra_pages:
            for mac in MAC_RE.findall(page):
                mac = mac.upper().replace("-", ":")
                if mac in seen:
                    continue
                seen.add(mac)
                devices.append(RouterDevice(mac=mac, hostname="unknown", interface="lan"))
        return devices

    def reachable(self) -> bool:
        try:
            self.refresh()
            return bool(self._html)
        except Exception:
            return False


def _is_private(ip: str) -> bool:
    try:
        a, b = (int(part) for part in ip.split(".")[:2])
    except (ValueError, IndexError):
        return True
    return a == 10 or a == 127 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or a == 0
