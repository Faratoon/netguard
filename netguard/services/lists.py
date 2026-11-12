"""Built-in category lists (adult / social / gaming / risky).

* ``adult``  - blocked for **everybody** by default (global blocklist)
* ``social`` / ``gaming`` / ``risky`` - blocked only on devices that have
  safe mode or an explicit category rule enabled
"""

ADULT = [
    "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com",
    "xhamster.com", "tube8.com", "spankbang.com", "fapello.com", "fapello.net",
    "onlyfans.com", "fanvue.com", "fansly.com", "camwhores.tv", "cam4.com",
    "chaturbate.com", "stripchat.com", "bongacams.com", "myfreecams.com",
    "livejasmin.com", "imlive.com", "flirt4free.com", "streamate.com", "thisav.com",
    "hentai.to", "hentai.tv", "rule34.xxx", "e-hentai.org", "nhentai.net",
    "hitomi.la", "hanime.tv", "tsumino.moe", "motherless.com", "pixiv.net",
    "saint.to", "e621.info", "booru.tv", "gelbooru.com", "fakku.net", "hitomi.me",
    "minagosh.pw", "nekohouse.su", "skebby.rip", "adultism.com", "sex.com",
    "escortbook.com", "backpage.com", "literotica.com", "adultgames.com",
    "xhamsterdaily.com", "pornhub-premium.com", "xvideos-porn.com", "erome.com",
    "rule34.paheal.net", "penisjax.com", "fucks.tv", "fap.org",
]

SOCIAL = [
    "facebook.com", "fbcdn.net", "messenger.com", "instagram.com",
    "cdninstagram.com", "threads.net", "snapchat.com", "sc-cdn.net", "twitter.com",
    "x.com", "twimg.com", "tiktok.com", "tiktokcdn.com", "musical.ly",
    "reddit.com", "redd.it", "discord.com", "discordapp.com", "discord.gg",
    "telegram.org", "telegram.me", "t.me", "whatsapp.com", "whatsapp.net",
    "tumblr.com", "pinterest.com", "vk.com", "weibo.com", "linkedin.com",
    "clubhouse.com", "houseparty.com", "nextdoor.com", "quora.com", "medium.com",
]

GAMING = [
    "roblox.com", "rbxcdn.com", "fortnite.com", "epicgames.com", "minecraft.net",
    "minecraftservices.com", "steampowered.com", "store.steampowered.com",
    "playstation.com", "store.playstation.com", "xboxlive.com", "xbox.com",
    "ea.com", "playea.com", "leagueoflegends.com", "riotgames.com", "valorant.com",
    "counter-strike.net", "activision.com", "blizzard.com", "ubisoft.com",
    "playubisoft.com", "gog.com", "itch.io", "nintendo.com",
    "switch.nintendo.com", "pokemon.com", "splatoon.nintendo.com", "curseforge.com",
    "modrinth.com", "twitch.tv", "ttvnw.net", "gamefaqs.gamespot.com",
    "ign.com", "gamespot.com", "us.playstation.com",
]

RISKY = [
    "omegle.com", "chaturbate.com", "ask.fm", "duckduckgo.com", "webcamsex.com",
    "chatroulette.com", "randomchat.com", "coomeo.com",
]

CATEGORY_LISTS: dict[str, list[str]] = {
    "adult": ADULT,
    "social": SOCIAL,
    "gaming": GAMING,
    "risky": RISKY,
}

#: categories that are blocked for every device on the network
GLOBAL_CATEGORIES = {"adult"}

#: categories blocked when a device has safe mode switched on
SAFE_MODE_CATEGORIES = {"adult", "social", "gaming", "risky"}
