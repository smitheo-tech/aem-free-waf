#!/usr/bin/env python3
"""
Offline regression test for config/cdn.yaml.

Evaluates every non-rate-limit rule against tests/samples.yaml:
  * attack samples must match at least one rule (optionally a specific one)
  * legit samples must not match any `block` rule (log matches are reported as warnings)

Request property simulation (mirrors Adobe's documented getters):
  url / path / queryString = as received (percent-encoded)
  urlRaw / pathRaw          = percent-decoded ("unescaped" per Adobe docs)
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
_cache: dict[str, re.Pattern] = {}


def rx(p: str) -> re.Pattern:
    if p not in _cache:
        _cache[p] = re.compile(p)
    return _cache[p]


def props(s: dict) -> dict:
    u = s["url"]
    parts = urlsplit(u)
    return {
        "url": u, "urlRaw": unquote(u),
        "path": parts.path, "pathRaw": unquote(parts.path),
        "queryString": parts.query,
        "method": s.get("method", "GET"), "tier": s.get("tier", "publish"),
        "domain": "www.example.com", "clientIp": s.get("ip", "198.51.100.7"),
        "clientCountry": s.get("country", "HR"), "clientAsNumber": s.get("asn", 5391),
    }


def getter(c: dict, p: dict, headers: dict):
    if "reqProperty" in c:
        return p.get(c["reqProperty"])
    if "reqHeader" in c:
        return headers.get(c["reqHeader"].lower())
    return None


def ev(c: dict, p: dict, h: dict) -> bool:
    if "allOf" in c:
        return all(ev(x, p, h) for x in c["allOf"])
    if "anyOf" in c:
        return any(ev(x, p, h) for x in c["anyOf"])
    v = getter(c, p, h)
    if "exists" in c:
        return (v is not None) == c["exists"]
    if v is None:
        return "doesNotMatch" in c or "doesNotEqual" in c or "notIn" in c
    if "equals" in c:
        return str(v) == str(c["equals"])
    if "doesNotEqual" in c:
        return str(v) != str(c["doesNotEqual"])
    if c.get("reqProperty") == "clientIp" and ("in" in c or "notIn" in c):
        ip = ipaddress.ip_address(v)
        inside = any(ip in ipaddress.ip_network(n, strict=False) for n in c.get("in", c.get("notIn")))
        return inside if "in" in c else not inside
    if "in" in c:
        return v in c["in"]
    if "notIn" in c:
        return v not in c["notIn"]
    if "matches" in c:
        return bool(rx(c["matches"]).search(str(v)))
    if "doesNotMatch" in c:
        return not rx(c["doesNotMatch"]).search(str(v))
    raise ValueError(f"unknown condition {c}")


def action_type(r: dict) -> str:
    a = r.get("action", "log")
    return a["type"] if isinstance(a, dict) else a


def main() -> int:
    import os
    cdn = yaml.safe_load(Path(os.environ.get("CDN_YAML", ROOT / "config" / "cdn.yaml")).read_text())
    all_rules = cdn["data"]["trafficFilters"]["rules"]
    present = {r["name"] for r in all_rules}
    # rate-limit rules: evaluate their condition too when a sample asks for them (expect: <name>)
    rules = [r for r in all_rules if "rateLimit" not in r]
    rl_rules = [r for r in all_rules if "rateLimit" in r]
    for r in rules:  # every regex must compile
        def walk(n):
            if isinstance(n, dict):
                for k in ("matches", "doesNotMatch"):
                    if k in n:
                        rx(n[k])
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        walk(r["when"])
    samples = yaml.safe_load((ROOT / "tests" / "samples.yaml").read_text())
    fails, warns = 0, 0
    for kind in ("attack", "legit"):
        for s in samples[kind]:
            h = {k.lower(): v for k, v in (s.get("headers") or {}).items()}
            h.setdefault("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15")
            if h["user-agent"] is None:
                del h["user-agent"]
            p = props(s)
            hits = [(r["name"], action_type(r)) for r in rules
                    if r["name"] not in (s.get("ignore") or []) and ev(r["when"], p, h)]
            if any(a == "allow" for _, a in hits[:1]):
                hits = hits[:1]
            label = s.get("name", s["url"])
            if kind == "attack":
                exp = s.get("expect")
                if exp and exp not in present:
                    print(f"skip   {label}  ({exp} not in this build – source unavailable or disabled)")
                    continue
                if exp and any(r["name"] == exp for r in rl_rules):
                    hits += [(r["name"], "ratelimit") for r in rl_rules if r["name"] == exp and ev(r["when"], p, h)]
                ok = bool(hits) and (exp is None or exp in [n for n, _ in hits])
                if not ok:
                    fails += 1
                    print(f"MISS   {label}  expected={exp} got={hits}")
            else:
                blocks = [n for n, a in hits if a == "block"]
                if blocks:
                    fails += 1
                    print(f"FP!    {label}  blocked by {blocks}")
                elif hits:
                    warns += 1
                    print(f"warn   {label}  logged by {[n for n, _ in hits]}")
    total = len(samples["attack"]) + len(samples["legit"])
    print(f"\n{total} samples, {fails} failures, {warns} log-only warnings, {len(rules)} rules evaluated")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
