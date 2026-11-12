"""Rule engine: domain matching, curfew evaluation and policy decisions."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Iterable

CATEGORY_PRESETS: dict[str, list[str]] = {
    "adult": [
        "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com",
        "xhamster.com", "onlyfans.com", "instagram.com/explore/tags", "tiktok.com",
        "reddit.com/r/nsfw", "9gag.com/gif", "brazzers.com", "hentai", "camwhores.tv",
    ],
    "social": [
        "facebook.com", "instagram.com", "snapchat.com", "twitter.com", "x.com",
        "tiktok.com", "reddit.com", "discord.com", "telegram.org", "tumblr.com",
    ],
    "gaming": [
        "roblox.com", "fortnite.com", "minecraft.net", "epicgames.com",
        "steampowered.com", "playstation.com", "xboxlive.com", "ea.com",
    ],
    "video": [
        "youtube.com", "netflix.com", "tiktok.com", "twitch.tv", "vimeo.com",
    ],
    "risky": [
        "omegle.com", "chaturbate.com", "ask.fm", "duckduckgo.com", "webcamsex.com",
    ],
}

#: Applications that commonly use microphones/cameras or are high risk for minors.
#: Blocking them at DNS level prevents the app from working at all.
MIC_SENSITIVE_APPS: dict[str, list[str]] = {
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "tiktok": ["tiktok.com", "tiktokcdn.com", "musical.ly"],
    "snapchat": ["snapchat.com", "sc-cdn.net"],
    "telegram": ["telegram.org", "t.me", "telegram.me"],
    "facebook-messenger": ["messenger.com", "facebook.com", "fbcdn.net"],
    "twitter": ["twitter.com", "x.com", "twimg.com"],
    "reddit": ["reddit.com", "redd.it"],
    "zoom": ["zoom.us", "zoomcdn.net"],
    "skype": ["skype.com", "skypeassets.com"],
    "twitch": ["twitch.tv", "ttvnw.net"],
    "roblox": ["roblox.com", "rbxcdn.com"],
}


@dataclass
class Decision:
    blocked: bool
    reason: str = ""
    category: str | None = None
    rule_id: int | None = None

    @property
    def allowed(self) -> bool:
        return not self.blocked


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    value = value.split("/")[0]
    value = value.split("?")[0]
    return value.strip(".")


def domain_matches(domain: str, pattern: str) -> bool:
    """Match a domain against a rule pattern.

    Supported patterns:
      * ``example.com``   -> the domain and all its subdomains
      * ``*.example.com`` -> subdomains only
      * ``*ads*``         -> substring match
    """
    domain = normalize_domain(domain)
    pattern = normalize_domain(pattern)
    if not domain or not pattern:
        return False
    if pattern.startswith("*."):
        return domain.endswith("." + pattern[2:])
    if "*" in pattern:
        regex = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
        return bool(re.match(regex, domain))
    return domain == pattern or domain.endswith("." + pattern)


def match_any(domains: Iterable[str], patterns: Iterable[str]) -> str | None:
    patterns = list(patterns)
    for domain in domains:
        for pattern in patterns:
            if domain_matches(domain, pattern):
                return pattern
    return None


def in_schedule(now: datetime, days: str, start: str, end: str) -> bool:
    """Return True when `now` falls inside the [start, end) window.

    The window belongs to the day it *starts* on: a 21:00-07:00 curfew listed
    for Monday covers Monday 21:00 until Tuesday 07:00.
    """
    try:
        day_list = {int(d) for d in days.split(",") if d.strip() != ""}
    except ValueError:
        day_list = {now.weekday()}
    if not day_list:
        return False

    start_t = _parse_time(start)
    end_t = _parse_time(end)
    now_t = now.time()

    if _crosses_midnight(start, end):
        if now_t >= start_t:
            return now.weekday() in day_list
        # early hours belong to the window that started the previous day
        return ((now.weekday() - 1) % 7) in day_list

    return now.weekday() in day_list and start_t <= now_t < end_t


def _crosses_midnight(start: str, end: str) -> bool:
    return _parse_time(start) >= _parse_time(end)


def _parse_time(value: str) -> time:
    try:
        hour, minute = value.split(":")
        return time(int(hour), int(minute))
    except Exception:
        return time(0, 0)


def remaining_curfew_time(now: datetime, start: str, end: str) -> timedelta:
    start_t = _parse_time(start)
    end_t = _parse_time(end)
    tzinfo = now.tzinfo
    if _crosses_midnight(start, end):
        if now.time() >= start_t:
            nxt = datetime.combine(now.date() + timedelta(days=1), end_t, tzinfo=tzinfo)
        else:
            nxt = datetime.combine(now.date(), end_t, tzinfo=tzinfo)
    else:
        nxt = datetime.combine(now.date(), end_t, tzinfo=tzinfo)
    return max(nxt - now, timedelta(0))
