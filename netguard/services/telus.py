"""Native parental-control APIs of the TELUS T3200M (Sagemcom fast-XXXX firmware).

The modem exposes three real control pages behind the admin login:

* **Website Blocking** (``urlfilter.cmd``)      - global URL/domain block list (max 25)
* **Services Blocking** (``serv_block.cmd``)    - per device: web / ftp / news / e-mail / im
* **Scheduling Access** (``detail_access.tod``) - per device curfew (weekdays + time window)

All three are plain ``POST`` requests with the session key of the logged-in
session, exactly like the modem's own JavaScript does it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .web_router import WebRouter

#: checkbox order of the services blocking page -> bit mask
SERVICE_BITS = {"web": 16, "ftp": 8, "newsgroups": 4, "email": 2, "im": 1}
SERVICE_NAMES = {v: k for k, v in SERVICE_BITS.items()}

WEEKDAY_BITS = {
    "Sunday": 1,
    "Monday": 2,
    "Tuesday": 4,
    "Wednesday": 8,
    "Thursday": 16,
    "Friday": 32,
    "Saturday": 64,
}

#: the modem's time selects use 15 minute steps starting at 00:00
TIME_STEPS = 96


@dataclass
class ScheduleRule:
    mac: str
    days: list[str]
    start_time: str
    end_time: str

    @property
    def days_mask(self) -> int:
        return sum(WEEKDAY_BITS[d] for d in self.days if d in WEEKDAY_BITS)


class TelusControls:
    """Drives the modem's own parental-control pages."""

    def __init__(self, router: WebRouter):
        self.router = router

    # ------------------------------------------------------------ session
    def _client(self):
        if not self.router._logged_in:
            self.router.login()
        return self.router._http()

    def session_key(self) -> str:
        client = self._client()
        page = client.get("/").text
        match = re.search(r"sessionKey\s*=\s*'?(\d+)'", page)
        if not match:
            match = re.search(r'name="sessionKey"\s+value="(\d+)"', page)
        return match.group(1) if match else "0"

    def _post(self, path: str, params: dict[str, object], thankyou: str) -> str:
        client = self._client()
        payload = {
            "sessionKey": self.session_key(),
            "needthankyou": thankyou,
            **params,
        }
        response = client.post(path, data=payload)
        return response.text

    # --------------------------------------------------- website blocking
    def list_blocked_urls(self) -> list[str]:
        client = self._client()
        page = client.get("/advancedsetup_websiteblocking.html").text
        match = re.search(r"var rules\s*=\s*'([^']*)'", page)
        if not match:
            return []
        raw = match.group(1)
        return [item for item in raw.split("|") if item]

    def add_blocked_url(self, url: str) -> dict:
        """Block a domain on the modem (the modem only accepts bare domains)."""
        domain = re.sub(r"^https?://", "", (url or "").strip()).split("/")[0]
        if not domain:
            raise ValueError("empty domain")
        client = self._client()
        text = self._post(
            "/urlfilter.cmd",
            {
                "action": "set_url",
                "TodUrlAdd": domain,
                "port_num": 80,
                "listtype": "Exclude",
            },
            "advancedsetup_websiteblocking.html",
        )
        return {"domain": domain, "ok": "msg=err" not in text, "rules": self.list_blocked_urls()}

    def remove_blocked_url(self, url: str) -> dict:
        domain = re.sub(r"^https?://", "", (url or "").strip()).split("/")[0]
        text = self._post(
            "/urlfilter.cmd",
            {"action": "remove_url", "rmLst": domain},
            "advancedsetup_websiteblocking.html",
        )
        return {"domain": domain, "ok": "msg=err" not in text, "rules": self.list_blocked_urls()}

    # --------------------------------------------------- services blocking
    def list_service_rules(self) -> list[dict]:
        client = self._client()
        page = client.get("/advancedsetup_servicesblocking.html").text
        match = re.search(r"var\s+allRule\s*=\s*'([^']*)'", page)
        if not match:
            match = re.search(r"var\s+ip_list\s*=\s*'([^']*)'", page)
            raw = match.group(1) if match else ""
        else:
            raw = match.group(1)
        rules: list[dict] = []
        for item in raw.split("|"):
            if not item or "/" not in item:
                continue
            ip, _, mask = item.partition("/")
            try:
                mask_value = int(mask)
            except ValueError:
                continue
            services = [name for bit, name in SERVICE_NAMES.items() if mask_value & bit]
            rules.append({"ip": ip, "mask": mask_value, "services": services})
        return rules

    def set_service_block(self, ip: str, services: list[str]) -> dict:
        """Block the given services for one device (web / ftp / newsgroups / email / im)."""
        mask = 0
        for service in services:
            mask |= SERVICE_BITS.get(service.lower(), 0)
        if not mask:
            raise ValueError("no service selected")
        text = self._post(
            "/serv_block.cmd",
            {"rules": f"{ip}/{mask}|", "command": "add"},
            "advancedsetup_servicesblocking.html",
        )
        return {"ip": ip, "services": services, "ok": "msg=err" not in text}

    def clear_service_block(self, ip: str, mask: int | None = None) -> dict:
        if mask is None:
            rule = next((r for r in self.list_service_rules() if r["ip"] == ip), None)
            if not rule:
                return {"ip": ip, "ok": True, "note": "no rule"}
            mask = rule["mask"]
        text = self._post(
            "/serv_block.cmd",
            {"rules": f"{ip}/{mask}|", "command": "del"},
            "advancedsetup_servicesblocking.html",
        )
        return {"ip": ip, "ok": "msg=err" not in text}

    # -------------------------------------------------- scheduling access
    def list_schedules(self) -> list[dict]:
        client = self._client()
        page = client.get("/advancedsetup_schedulingaccess.html").text
        rows: list[dict] = []
        for mac, days, start, end in re.findall(
            r"(\d{2}(?::\d{2}){5})\D{0,200}?(\d+)\D{0,120}?(\d+)\D{0,120}?(\d+)", page
        ):
            rows.append({"mac": mac.upper(), "raw": (days, start, end)})
        return rows

    def add_schedule(self, mac: str, days: list[str], start: str, end: str) -> dict:
        mac = mac.upper().replace("-", ":")
        mask = sum(WEEKDAY_BITS[d] for d in days if d in WEEKDAY_BITS)
        if not mask:
            raise ValueError("no weekday selected")
        start_index = _time_to_index(start)
        end_index = _time_to_index(end)
        text = self._post(
            "/detail_access.tod",
            {
                "action": "add",
                "mac": mac,
                "days": mask,
                "start_time": start_index,
                "end_time": end_index,
            },
            "advancedsetup_schedulingaccess.html",
        )
        return {"mac": mac, "days": days, "start": start, "end": end, "ok": "msg=err" not in text}

    def remove_schedule(self, mac: str) -> dict:
        mac = mac.upper().replace("-", ":")
        text = self._post(
            "/detail_access.tod",
            {"action": "remove", "rmLst": mac},
            "advancedsetup_schedulingaccess.html",
        )
        return {"mac": mac, "ok": "msg=err" not in text}


def _time_to_index(value: str) -> int:
    """21:30 -> index of the matching 15 minute slot (the modem uses 15 min steps)."""
    try:
        hour, minute = (int(part) for part in value.split(":"))
    except ValueError:
        return 0
    return min(max(hour * 4 + minute // 15, 0), TIME_STEPS - 1)
