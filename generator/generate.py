#!/usr/bin/env python3
"""
aem-free-waf generator
======================
Builds an AEM as a Cloud Service `config/cdn.yaml` made only of STANDARD
traffic-filter rules (no `wafFlags`, so no Extended Security / WAF-DDoS licence),
from continuously maintained public sources:

  * OWASP Core Rule Set (CRS) – data lists + paranoia-level-1 regex rules
      https://github.com/coreruleset/coreruleset            (Apache-2.0)
  * X4BNet datacenter ASN list
      https://github.com/X4BNet/lists_vpn                   (MIT)
  * Tor Project bulk exit list (optional)
      https://check.torproject.org/torbulkexitlist

Usage:
  python generator/generate.py                    # writes config/cdn.yaml + build-report.md
  python generator/generate.py --cache .cache     # reuse downloaded sources (offline dev)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bots  # noqa: E402
import signals  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CRS_RAW = "https://raw.githubusercontent.com/coreruleset/coreruleset/{ref}/rules/{file}"
X4B_ASN = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt"
TOR_URLS = [
    "https://check.torproject.org/torbulkexitlist",
    "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
]
CRS_CONF_FILES = {
    "921": "REQUEST-921-PROTOCOL-ATTACK.conf",
    "930": "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "931": "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "932": "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "941": "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "942": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "943": "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
    "944": "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
}
# CRS data list -> (rule name, target, CRS rule id it comes from)
CRS_DATA_LISTS = {
    "scanners-user-agents.data": ("crs-913-scanner-user-agents", "ua", 913100),
    "restricted-files.data": ("crs-930-restricted-files", "path", 930130),
    "lfi-os-files.data": ("crs-930-lfi-os-files", "args", 930120),
    "unix-shell.data": ("crs-932-unix-shell", "args", 932160),
    "windows-powershell-commands.data": ("crs-932-powershell", "args", 932120),
    "ssrf.data": ("crs-934-ssrf", "args", 934110),
    "java-classes.data": ("crs-944-java-classes", "args", 944130),
}
# Search engines / link unfurlers that live in cloud ASNs – never rate-limit them
GOOD_BOTS_UA = (r"(?i)(googlebot|bingbot|adsbot-google|google-inspectiontool|storebot-google|"
                r"applebot|duckduckbot|linkedinbot|facebookexternalhit|slackbot|twitterbot)")
MAX_BYTES = 100_000


# --------------------------------------------------------------------------- fetching
class Fetcher:
    def __init__(self, cache: Path | None):
        self.cache = cache
        if cache:
            cache.mkdir(parents=True, exist_ok=True)
        ca = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
        self.ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()

    def get(self, url: str) -> str:
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-150:]
        if self.cache and (self.cache / key).exists():
            return (self.cache / key).read_text(encoding="utf-8")
        req = urllib.request.Request(url, headers={"User-Agent": "aem-free-waf-generator"})
        with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
            text = r.read().decode("utf-8", "replace")
        if self.cache:
            (self.cache / key).write_text(text, encoding="utf-8")
        return text


def latest_crs_tag() -> str:
    out = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", "https://github.com/coreruleset/coreruleset.git", "v4.*"],
        capture_output=True, text=True, check=True).stdout
    tags = [l.rsplit("/", 1)[1] for l in out.splitlines()
            if re.search(r"refs/tags/v4\.\d+\.\d+$", l)]
    return max(tags, key=lambda t: tuple(int(x) for x in t[1:].split(".")))


# --------------------------------------------------------------------------- regex helpers
def data_entries(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or not s.isascii():
            continue
        out.append(s)
    return sorted(set(out))


def trie_regex(words: list[str]) -> str:
    """Compact alternation (like regexp-assemble) so long lists fit the 100 KB budget."""
    trie: dict = {}
    for w in words:
        node = trie
        for ch in w.lower():
            node = node.setdefault(ch, {})
        node[""] = True

    def build(node: dict) -> str:
        end = "" in node
        branches = []
        for ch in sorted(k for k in node if k):
            sub, child = ch, node[ch]
            # collapse single-child chains
            while len(child) == 1 and "" not in child:
                (nxt, child), = child.items()
                sub += nxt
            if "" in child and len(child) == 1:
                branches.append(re.escape(sub))
            else:
                branches.append(re.escape(sub) + build(child))
        if not branches:
            return ""
        if len(branches) == 1 and not end:
            return branches[0]
        body = "|".join(branches)
        return f"(?:{body})" + ("?" if end else "")

    return build(trie)


def _scan(rx: str, plus_as_space: bool, anchor_args: bool) -> str:
    """Rewrite a CRS regex so it works on a whole decoded query string:
       ^ / $ become argument-boundary anchors, \\s also matches '+'."""
    out, i, in_cls = [], 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            pair = rx[i:i + 2]
            if plus_as_space and pair == r"\s":
                out.append(r"\s+" if in_cls else r"[\s+]")
            else:
                out.append(pair)
            i += 2
            continue
        if in_cls:
            if c == "]" and not (out and out[-1] in ("[", "[^")):
                in_cls = False
            out.append(c)
        elif c == "[":
            in_cls = True
            if rx[i + 1:i + 2] == "^":
                out.append("[^"); i += 2
                if rx[i:i + 1] == "]":
                    out.append("]"); i += 1
                continue
            out.append(c)
            if rx[i + 1:i + 2] == "]":
                out.append("]"); i += 1
        elif anchor_args and c == "^" and not (out and out[-1] == "(?"):
            out.append(r"(?:^|(?<=[?&=]))")
        elif anchor_args and c == "$":
            out.append(r"(?:$|(?=&))")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def to_cdn_regex(rx: str, target: str) -> str:
    rx = rx.strip()
    if rx.startswith("(?i)"):
        rx = rx[4:]
    rx = rx.replace("(?i)", "")  # mid-pattern global flags are not portable; we go case-insensitive anyway
    if target == "args":
        rx = _scan(rx, plus_as_space=True, anchor_args=True)
        return r"(?i)\?.*?(?:" + rx + ")"
    if target == "url":
        rx = _scan(rx, plus_as_space=True, anchor_args=False)
    return "(?i)" + rx


def compiles(rx: str) -> bool:
    try:
        re.compile(rx)
        return True
    except re.error:
        return False


# --------------------------------------------------------------------------- CRS parsing
def parse_crs_conf(text: str) -> dict[int, dict]:
    text = re.sub(r"\\\n\s*", " ", text)
    rules, chain_open = {}, False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("SecRule "):
            continue
        m = re.match(r'SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s*(?:"((?:[^"\\]|\\.)*)")?', line)
        if not m:
            continue
        variables, op, act = m.group(1), m.group(2).replace('\\"', '"'), (m.group(3) or "")
        acts = [a.strip() for a in act.split(",")]
        if chain_open:  # continuation of a chained rule -> mark parent as chained
            chain_open = "chain" in acts
            continue
        idm = re.search(r"\bid:(\d+)", act)
        chain_open = "chain" in acts
        if idm:
            rules[int(idm.group(1))] = {"vars": variables, "op": op, "chained": chain_open,
                                        "pl": (re.search(r"paranoia-level/(\d)", act) or [None, None])[1]}
    return rules


def crs_target(variables: str) -> str:
    v = variables.upper()
    if "REQUEST_FILENAME" in v or "REQUEST_URI" in v or "REQUEST_LINE" in v:
        return "url"
    if "ARGS" in v or "QUERY_STRING" in v:
        return "args"
    if "REQUEST_HEADERS" in v:
        return "ua"
    return "skip"


# --------------------------------------------------------------------------- rule builders
def cond(target: str, rx: str, cfg: dict) -> dict:
    if target == "ua":
        return {"reqHeader": "user-agent", "matches": rx}
    if target == "path":
        return {"reqProperty": cfg["decodedPathProperty"], "matches": rx}
    return {"reqProperty": cfg["decodedUrlProperty"], "matches": rx}


def action(name: str, cfg: dict):
    a = cfg["actions"].get(name, "log")
    return {"type": a, "alert": True} if name in cfg.get("alerts", []) else a


def make_rule(name: str, conditions: list[dict], cfg: dict) -> dict:
    when = conditions[0] if len(conditions) == 1 else {"anyOf": conditions}
    return {"name": name, "when": when, "action": action(name, cfg)}


# --------------------------------------------------------------------------- YAML output
class Dumper(yaml.SafeDumper):
    pass


def _str(dumper, s):
    style = "'" if ("\\" in s or any(c in s for c in ":#{}[]&*!|>%@`\"")) and "\n" not in s else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)


def _list(dumper, data):
    flow = all(isinstance(x, (str, int, float)) for x in data)
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=flow)


Dumper.add_representer(str, _str)
Dumper.add_representer(list, _list)


def dump(obj) -> str:
    return yaml.dump(obj, Dumper=Dumper, sort_keys=False, width=10**9, allow_unicode=False,
                     default_flow_style=False)


def rules_size(rules: list[dict]) -> int:
    return len(dump(rules).encode()) if rules else 0


# --------------------------------------------------------------------------- robots.txt
def write_robots(path: Path, robots_cfg: dict, ai_tokens: list[str], ai_list_failed: bool,
                 notes: list[str]) -> bool:
    """Writes robots.txt; returns True if it changed. If the AI crawler list was unreachable the
    previous tokens are kept, so an outage can't silently reopen the site to those crawlers while
    config edits still apply."""
    if not robots_cfg:
        return False
    if ai_list_failed:
        previous = path.read_text() if path.exists() else ""
        ai_tokens = signals.previous_ai_tokens(previous)
        notes.append("robots.txt: ai.robots.txt unavailable, kept the previous AI crawler list"
                     if ai_tokens else
                     "WARNING robots.txt: ai.robots.txt unavailable and no previous list, "
                     "the AI crawler group is missing")
    text = signals.render_robots(robots_cfg, ai_tokens)
    if path.exists() and path.read_text() == text:
        return False
    path.write_text(text)
    return True


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "waf-config.yaml"))
    ap.add_argument("--base", default=str(ROOT / "base-rules.yaml"))
    ap.add_argument("--out", default=str(ROOT / "config" / "cdn.yaml"))
    ap.add_argument("--report", default=str(ROOT / "build-report.md"))
    ap.add_argument("--cache", default=None, help="cache downloaded sources here")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    base = yaml.safe_load(Path(args.base).read_text())
    f = Fetcher(Path(args.cache) if args.cache else None)
    notes: list[str] = []

    ref = cfg.get("crsRef", "latest")
    if ref == "latest":
        try:
            ref = latest_crs_tag()
        except Exception as e:  # noqa: BLE001
            notes.append(f"Could not resolve latest CRS tag ({e}); using main")
            ref = "main"

    sections: dict[str, list[dict]] = {}
    origin: dict[str, str] = {}

    # ---- CRS data lists
    for fname, (name, target, crs_id) in CRS_DATA_LISTS.items():
        words = data_entries(f.get(CRS_RAW.format(ref=ref, file=fname)))
        alt = trie_regex(words)
        rx = (r"(?i)\?.*?" + alt) if target == "args" else "(?i)" + alt
        if not compiles(rx):
            notes.append(f"{name}: generated regex did not compile, skipped")
            continue
        sections[name] = [make_rule(name, [cond(target, rx, cfg)], cfg)]
        origin[name] = f"CRS {ref} `{fname}` ({len(words)} entries, rule {crs_id})"

    # ---- CRS regex rules
    parsed: dict[int, dict] = {}
    for fam, fname in CRS_CONF_FILES.items():
        parsed.update(parse_crs_conf(f.get(CRS_RAW.format(ref=ref, file=fname))))
    for name, ids in cfg["crsRegexRules"].items():
        conds, used = [], []
        for rid in ids:
            r = parsed.get(rid)
            if not r:
                notes.append(f"{name}: CRS rule {rid} not found in {ref} (removed upstream?)"); continue
            if r["chained"] or not r["op"].startswith("@rx "):
                notes.append(f"{name}: CRS rule {rid} is chained/non-regex, skipped"); continue
            target = crs_target(r["vars"])
            if target == "skip":
                notes.append(f"{name}: CRS rule {rid} targets {r['vars'][:40]}, not portable"); continue
            rx = to_cdn_regex(r["op"][4:], target)
            if not compiles(rx):
                notes.append(f"{name}: CRS rule {rid} uses regex syntax not portable, skipped"); continue
            conds.append(cond(target, rx, cfg)); used.append(rid)
            # small header-targeting rules (e.g. Shellshock 932170) also check User-Agent/Referer
            if target != "ua" and "REQUEST_HEADERS" in r["vars"].upper() and len(r["op"]) < 400:
                hrx = to_cdn_regex(r["op"][4:], "ua")
                if compiles(hrx):
                    conds.append({"reqHeader": "user-agent", "matches": hrx})
                    if "!REQUEST_HEADERS:Referer" not in r["vars"]:
                        conds.append({"reqHeader": "referer", "matches": hrx})
        if conds:
            sections[name] = [make_rule(name, conds, cfg)]
            origin[name] = f"CRS {ref} rules " + ", ".join(map(str, used))

    # ---- Datacenter ASNs (rate limit, not block)
    if cfg.get("rateLimitDatacenterAsns"):
        asns = sorted({int(m.group(1)) for m in re.finditer(r"^AS(\d+)", f.get(X4B_ASN), re.M)})
        sections["ratelimit-datacenter-asn"] = [{
            "name": "ratelimit-datacenter-asn",
            "when": {"allOf": [
                {"reqProperty": "tier", "equals": "publish"},
                {"reqProperty": "clientAsNumber", "in": asns},
                {"reqHeader": "user-agent", "doesNotMatch": GOOD_BOTS_UA}]},
            "rateLimit": {"limit": 20, "window": 10, "penalty": 600, "count": "all",
                          "groupBy": [{"reqProperty": "clientIp"}]},
            "action": action("ratelimit-datacenter-asn", cfg)}]
        origin["ratelimit-datacenter-asn"] = f"X4BNet/lists_vpn datacenter ASN list ({len(asns)} ASNs)"

    # ---- Tor exit nodes (optional)
    if cfg.get("blockTorExitNodes"):
        ips, src = [], None
        for u in TOR_URLS:
            try:
                ips = sorted({l.strip() for l in f.get(u).splitlines()
                              if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", l.strip())})
                if ips:
                    src = u; break
            except Exception as e:  # noqa: BLE001
                notes.append(f"Tor list {u} failed: {e}")
        if ips:
            sections["tor-exit-nodes"] = [{"name": "tor-exit-nodes",
                                           "when": {"reqProperty": "clientIp", "in": ips},
                                           "action": action("tor-exit-nodes", cfg)}]
            origin["tor-exit-nodes"] = f"{src} ({len(ips)} IPs)"

    # ---- bots, crawlers, AI agents
    ai_tokens: list[str] = []
    ai_list_failed = False
    if cfg.get("bots"):
        bsec, borig, ai_tokens, failed = bots.build(f.get, cfg, notes)
        ai_list_failed = "bots-ai-block" in failed
        sections.update(bsec); origin.update(borig)
        # source temporarily unreachable -> keep the previous build's rule (no flapping PRs)
        prev_path = Path(args.out)
        if failed and prev_path.exists():
            prev = {r["name"]: r for r in (yaml.safe_load(prev_path.read_text()) or {})
                    .get("data", {}).get("trafficFilters", {}).get("rules", [])}
            for name in sorted(failed):
                if name in prev and name not in sections:
                    sections[name] = [prev[name]]
                    origin[name] = "previous build (source unavailable this run)"
                    notes.append(f"{name}: source unavailable, kept previous version")

    # ---- base rules + allowlist
    allow = []
    if cfg.get("allowlistIps"):
        allow = [{"name": "allow-trusted-ips",
                  "when": {"reqProperty": "clientIp", "in": cfg["allowlistIps"]}, "action": "allow"}]
    base_before = allow + (base.get("before") or [])
    base_after = base.get("after") or []
    robots_cfg = cfg.get("robots") or {}
    response_rules = signals.response_rules(robots_cfg)

    # ---- size budget by priority
    budget = int(cfg.get("sizeBudgetBytes", 97000))
    used = rules_size(base_before + base_after + response_rules) + 2500  # + header/wrapper
    kept, skipped = [], []
    for name in cfg["priority"]:
        if name == "base" or name not in sections:
            continue
        sz = rules_size(sections[name])
        if used + sz <= budget:
            kept.append(name); used += sz
        else:
            skipped.append((name, sz))
    for name in sections:
        if name not in cfg["priority"]:
            notes.append(f"{name} has no priority entry, not included")

    generated = [r for n in kept for r in sections[n]]
    rules = base_before + generated + base_after
    names = [r["name"] for r in rules]
    assert len(names) == len(set(names)), "duplicate rule names"
    for n in names:
        assert len(n) <= 64 and re.fullmatch(r"[A-Za-z0-9-]+", n), f"bad rule name {n}"

    data: dict = {"trafficFilters": {"rules": rules}}
    if response_rules:
        data["responseTransformations"] = {"rules": response_rules}
    doc = {"kind": "CDN", "version": "1", "metadata": {"envTypes": cfg["envTypes"]}, "data": data}
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# =====================================================================",
        "# GENERATED by aem-free-waf (generator/generate.py) – DO NOT EDIT BY HAND.",
        "# Edit waf-config.yaml / base-rules.yaml and re-run the generator.",
        f"# Built: {now}",
        "# Standard traffic filter rules only – no wafFlags, no WAF licence needed.",
        "# Sources:",
        *[f"#   {n}: {origin[n]}" for n in kept],
        "# OWASP CRS is (c) OWASP CRS project, Apache-2.0. X4BNet lists: MIT.",
        "# =====================================================================",
    ]
    body = "\n".join(header) + "\n" + dump(doc)
    size = len(body.encode())
    if size > MAX_BYTES:
        print(f"ERROR: cdn.yaml would be {size} bytes (> {MAX_BYTES}); lower sizeBudgetBytes", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    old = out.read_text() if out.exists() else ""
    strip = lambda t: re.sub(r"^#.*$", "", t, flags=re.M)  # compare rules only, not header comments  # noqa: E731
    changed = strip(old) != strip(body)
    if changed:
        out.write_text(body)
    if write_robots(out.parent / "robots.txt", robots_cfg, ai_tokens, ai_list_failed, notes):
        changed = True

    rep = [f"## aem-free-waf build ({now})", "",
           f"- OWASP CRS ref: **{ref}**",
           f"- cdn.yaml size: **{size:,} bytes** of {MAX_BYTES:,} allowed",
           f"- Rules: **{len(rules)}** ({len(generated)} generated, {len(rules) - len(generated)} hand-maintained)",
           f"- Changed vs previous: **{'yes' if changed else 'no'}**", "",
           "| Generated rule | Action | Source |", "|---|---|---|"]
    def act_of(n):
        r = sections[n][0]
        a = r["action"]["type"] if isinstance(r["action"], dict) else r["action"]
        return f"rate limit → {a}" if "rateLimit" in r else a
    rep += [f"| `{n}` | {act_of(n)} | {origin[n]} |" for n in kept]
    if skipped:
        rep += ["", "**Skipped – size budget:** " + ", ".join(f"`{n}` ({s:,} B)" for n, s in skipped)]
    if notes:
        rep += ["", "<details><summary>Notes</summary>", "", *[f"- {n}" for n in notes], "", "</details>"]
    Path(args.report).write_text("\n".join(rep) + "\n")
    print("\n".join(rep))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write(f"changed={'true' if changed else 'false'}\ncrs_ref={ref}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
