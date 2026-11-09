"""
Bot, crawler, scanner and AI-agent rules for aem-free-waf.

Sources (all fetched at build time, so the rules track upstream changes):
  * ai-robots-txt/ai.robots.txt  robots.json – community list of AI crawlers / agents
  * Vendor-published IP ranges   – Google, Bing, OpenAI, Perplexity, Apple, Anthropic, Mistral
    (used to catch impostors: UA claims to be the bot, IP is not in the vendor's list)

Design rules:
  * Never emit `allow` for anything identified by User-Agent – a UA is trivially spoofed and
    `allow` would skip every other rule.
  * A vendor rule is only emitted when ALL of that vendor's IP lists were fetched; a partial
    list would block the real bot.
"""
from __future__ import annotations

import ipaddress
import json
import re

AI_ROBOTS_URL = "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json"

# token boundary so short names ("Dot", "Code") don't match inside other words ("LinkedInBot")
def token_regex(names: list[str]) -> str:
    # lower-cased first: the regex is (?i), and upstream lists some names in two spellings, which
    # would otherwise tie in the sort and reorder the output between runs (hash randomization)
    alt = "|".join(re.escape(n) for n in sorted({n.lower() for n in names}, key=lambda s: (-len(s), s)))
    return r"(?i)(?:^|[\s(;,+])(?:" + alt + r")(?:[/\s;),]|$)"


def classify(function: str) -> str:
    f = (function or "").lower()
    if "assistant" in f or "on behalf" in f or "user request" in f or "user prompt" in f or "user-initiated" in f:
        return "ai-assistants"
    if "agent" in f:
        return "ai-agents"
    if re.search(r"\bsearch", f):  # word boundary: "research" is not search
        return "ai-search"
    if "data provider" in f:
        return "ai-data-providers"
    if re.search(r"train|scrap|llm|dataset|machine learning|language model", f):
        return "ai-training"
    return "ai-other"


def robots_token(name: str) -> str:
    """RFC 9309 product token: the leading run of token characters ("Brightbot 1.0" -> "Brightbot")."""
    return re.sub(r"[^A-Za-z0-9_-].*$", "", name)


def extract_cidrs(text: str) -> list[str]:
    """Vendor files are JSON with ipv4Prefix/ipv6Prefix (Google/Bing/OpenAI/Perplexity/Apple)
    or similar; extract every valid IP/CIDR string robustly."""
    out = set()
    try:
        blob = json.dumps(json.loads(text))
    except ValueError:
        blob = text
    for tok in re.findall(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?", blob):
        if ("." not in tok and ":" not in tok) or len(tok) < 7:
            continue
        try:
            out.add(str(ipaddress.ip_network(tok, strict=False)))
        except ValueError:
            pass
    return collapse(out)


def collapse(cidrs) -> list[str]:
    """Merge adjacent/overlapping ranges per IP version to save cdn.yaml bytes."""
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    out = []
    for v in (4, 6):
        out += [str(n) for n in ipaddress.collapse_addresses(n for n in nets if n.version == v)]
    return out


def build(fetch, cfg: dict, notes: list[str]):
    """Returns (sections, origin, ai_tokens, failed). `ai_tokens` = robots.txt tokens of the bots
    the policy blocks (rate-limited bots are admitted, so robots.txt must not refuse them); `failed` = rule names whose source could not be fetched this
    run (the caller keeps the previous version of those)."""
    bc = cfg.get("bots", {})
    failed: set[str] = set()
    sections: dict[str, list[dict]] = {}
    origin: dict[str, str] = {}
    exclude_ua = []  # UA tokens of verified vendors – excluded from the generic crawler limit

    # ------------------------------------------------ 1. impostors of verified bots
    for vendor, spec in (bc.get("verifiedVendors") or {}).items():
        cidrs, ok = set(), True
        for group in spec["ipLists"]:            # each group = alternative URLs for one list
            got = None
            for url in group if isinstance(group, list) else [group]:
                try:
                    c = extract_cidrs(fetch(url))
                    if c:
                        got = (url, c); break
                except Exception as e:  # noqa: BLE001
                    notes.append(f"bots/{vendor}: {url} failed ({type(e).__name__})")
            if not got:
                ok = False; break
            cidrs.update(got[1])
        exclude_ua.append(spec["ua"])
        if not ok:
            failed.add(f"bots-fake-{vendor}")
            notes.append(f"bots/{vendor}: not all IP lists available – impostor rule NOT emitted "
                         f"(a partial list would block the real bot)")
            continue
        name = f"bots-fake-{vendor}"
        cidr_list = collapse(cidrs)
        sections[name] = [{
            "name": name,
            "when": {"allOf": [
                {"reqHeader": "user-agent", "matches": "(?i)" + spec["ua"]},
                {"reqProperty": "clientIp", "notIn": cidr_list}]},
            "action": cfg["actions"].get(name, bc.get("impostorAction", "log"))}]
        origin[name] = f"{vendor} published IP ranges ({len(cidr_list)} prefixes)"

    # ------------------------------------------------ 2. AI crawlers / agents by purpose
    ai_tokens: set[str] = set()
    try:
        data = json.loads(fetch(AI_ROBOTS_URL))
    except Exception as e:  # noqa: BLE001
        data = {}
        notes.append(f"bots/ai.robots.txt failed ({type(e).__name__}) – AI policy rules not emitted")
    if not data or not isinstance(data, dict):  # an empty feed must not wipe the AI policy either
        data = {}
        failed.update({"bots-ai-block", "bots-ai-ratelimit", "bots-ai-log"})
    overrides = {k.lower(): v for k, v in (bc.get("aiOverrides") or {}).items()}
    policy = bc.get("aiPolicy", {})
    by_action: dict[str, dict[str, list[str]]] = {}
    counts: dict[str, int] = {}
    for name, meta in data.items():
        if name.startswith("__") or not name.isascii():
            continue
        cat = classify(meta.get("function", ""))
        act = overrides.get(name.lower(), policy.get(cat, "log"))
        counts[cat] = counts.get(cat, 0) + 1
        if act == "allow":
            continue
        by_action.setdefault(act, {}).setdefault(cat, []).append(name)
        if act == "block":
            ai_tokens.add(robots_token(name))
    for act, cats in by_action.items():
        names = [n for lst in cats.values() for n in lst]
        rule_name = {"block": "bots-ai-block", "ratelimit": "bots-ai-ratelimit", "log": "bots-ai-log"}[act]
        rule = {"name": rule_name, "when": {"reqHeader": "user-agent", "matches": token_regex(names)}}
        if act == "ratelimit":
            rule["rateLimit"] = dict(bc.get("rateLimit", {"limit": 10, "window": 60, "penalty": 600}),
                                     groupBy=[{"reqProperty": "clientIp"}])
            rule["action"] = "block"
        else:
            rule["action"] = act
        sections[rule_name] = [rule]
        origin[rule_name] = "ai.robots.txt: " + ", ".join(f"{c} ({len(v)})" for c, v in sorted(cats.items()))
    if data:
        notes.append("bots/ai.robots.txt categories: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    # ------------------------------------------------ 3. HTTP libraries / headless browsers
    libs = bc.get("httpLibraryUserAgents")
    if libs:
        sections["bots-http-libraries"] = [{
            "name": "bots-http-libraries",
            "when": {"allOf": [{"reqProperty": "tier", "equals": "publish"},
                               {"reqHeader": "user-agent", "matches": "(?i)(" + "|".join(libs) + ")"}]},
            "rateLimit": dict(bc.get("rateLimit", {"limit": 10, "window": 60, "penalty": 600}),
                              groupBy=[{"reqProperty": "clientIp"}]),
            "action": cfg["actions"].get("bots-http-libraries", "log")}]
        origin["bots-http-libraries"] = f"{len(libs)} HTTP-library / headless UA patterns (waf-config.yaml)"

    # ------------------------------------------------ 4. any other self-declared crawler
    if bc.get("genericCrawlerRateLimit", True):
        conds = [{"reqProperty": "tier", "equals": "publish"},
                 {"reqHeader": "user-agent",
                  "matches": r"(?i)(bot\b|bot/|crawl|spider|scrap|slurp|archiver|fetcher|preview|indexer)"}]
        if exclude_ua:
            conds.append({"reqHeader": "user-agent", "doesNotMatch": "(?i)(" + "|".join(exclude_ua) + ")"})
        sections["bots-generic-crawler-ratelimit"] = [{
            "name": "bots-generic-crawler-ratelimit",
            "when": {"allOf": conds},
            "rateLimit": dict(bc.get("rateLimit", {"limit": 10, "window": 60, "penalty": 600}),
                              groupBy=[{"reqProperty": "clientIp"}]),
            "action": cfg["actions"].get("bots-generic-crawler-ratelimit", "log")}]
        origin["bots-generic-crawler-ratelimit"] = "self-declared crawlers not covered by a verified vendor"

    # ------------------------------------------------ 5. cryptographically signed agents (Web Bot Auth)
    if bc.get("logSignedAgents", True):
        sections["bots-signed-agents"] = [{
            "name": "bots-signed-agents",
            "when": {"reqHeader": "signature-agent", "exists": True},
            "action": "log"}]
        origin["bots-signed-agents"] = "Web Bot Auth Signature-Agent header (ChatGPT agent, Google agent, ...)"

    return sections, origin, sorted(ai_tokens), failed
