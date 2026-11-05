"""Tests for robots.txt rendering and the Content-Usage response rule (generator/signals.py)."""
import re
from pathlib import Path

import pytest
import signals
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = {
    "contentSignal": "search=yes, ai-input=yes, ai-train=no",
    "contentUsage": "train-ai=n",
    "usageTokens": ["__usage_ai-training"],
    "trainingOptOutTokens": ["Google-Extended", "Applebot-Extended"],
    "allowPaths": ["/etc.clientlibs/"],
    "disallowPaths": ["/bin/", "/libs/", "/etc/"],
    "disallowQueryParams": ["q", "sort"],
    "sitemaps": ["https://www.example.com/sitemap.xml"],
}


def parse_groups(text: str) -> list[dict]:
    """Minimal RFC 9309 group parser: consecutive User-agent lines open one group."""
    groups: list[dict] = []
    in_agents = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if not in_agents:
                groups.append({"agents": [], "rules": []})
            groups[-1]["agents"].append(value.lower())
            in_agents = True
        elif key != "sitemap":
            in_agents = False
            if groups:
                groups[-1]["rules"].append((key, value))
    return groups


def group_for(groups: list[dict], agent: str) -> dict:
    named = [g for g in groups if agent.lower() in g["agents"]]
    return named[0] if named else next(g for g in groups if "*" in g["agents"])


def can_crawl(text: str, agent: str, url: str) -> bool:
    """RFC 9309 evaluation: longest match wins, Allow wins ties, * and $ supported."""
    best_len, allowed = -1, True
    for key, pattern in group_for(parse_groups(text), agent)["rules"]:
        if key not in ("allow", "disallow") or not pattern:
            continue
        rx = re.escape(pattern).replace(r"\*", ".*")
        rx = rx[:-2] + "$" if rx.endswith(r"\$") else rx
        longer = len(pattern) > best_len or (len(pattern) == best_len and key == "allow")
        if longer and re.match(rx, url):
            best_len, allowed = len(pattern), key == "allow"
    return allowed


@pytest.fixture
def robots() -> str:
    return signals.render_robots(CONFIG, ["GPTBot", "CCBot", "GPTBot"])


@pytest.mark.parametrize(
    ("agent", "url", "expected"),
    [
        ("Googlebot", "/content/site/en.html", True),
        ("Googlebot", "/etc.clientlibs/site/clientlibs/site.min.css", True),
        ("Googlebot", "/content/dam/site/hero.jpg", True),
        ("Googlebot", "/content/site/en.html?page=2", True),
        ("Googlebot", "/bin/querybuilder.json", False),
        ("Googlebot", "/libs/granite/core/content/login.html", False),
        ("Googlebot", "/etc/designs/x.css", False),
        ("Googlebot", "/content/site/en/search.html?q=shoes", False),
        ("Googlebot", "/content/site/en/list.html?page=2&sort=asc", False),
        ("Googlebot", "/content/site/en/list.html?faq=1", True),
        ("OAI-SearchBot", "/content/site/en.html", True),
        ("GPTBot", "/content/site/en.html", False),
        ("Google-Extended", "/content/site/en.html", False),
        ("Applebot-Extended", "/content/site/en.html", False),
        ("__usage_ai-training", "/content/site/en.html", False),
    ],
)
def test_crawl_policy(robots: str, agent: str, url: str, expected: bool) -> None:
    assert can_crawl(robots, agent, url) is expected


def test_preferences_sit_in_the_wildcard_group(robots: str) -> None:
    rules = group_for(parse_groups(robots), "*")["rules"]
    assert ("content-signal", "search=yes, ai-input=yes, ai-train=no") in rules
    assert ("content-usage", "train-ai=n") in rules


def test_ai_tokens_are_deduplicated(robots: str) -> None:
    assert robots.count("User-agent: GPTBot\n") == 1


def test_sitemap_and_reservation_comment(robots: str) -> None:
    assert "Sitemap: https://www.example.com/sitemap.xml\n" in robots
    assert "2019/790" in robots


def test_missing_sitemap_leaves_a_hint_not_a_directive() -> None:
    text = signals.render_robots({**CONFIG, "sitemaps": []}, [])
    assert not re.search(r"^Sitemap:", text, re.MULTILINE)
    assert "robots.sitemaps" in text


def test_relative_sitemap_is_rejected() -> None:
    with pytest.raises(ValueError, match="absolute"):
        signals.render_robots({**CONFIG, "sitemaps": ["/sitemap.xml"]}, [])


def test_response_rule_uses_adobe_syntax() -> None:
    assert signals.response_rules(CONFIG) == [
        {
            "name": "set-content-usage-header",
            "when": {"reqProperty": "tier", "equals": "publish"},
            "actions": [{"type": "set", "respHeader": "Content-Usage", "value": "train-ai=n"}],
        }
    ]


def test_response_rule_omitted_without_preference() -> None:
    assert signals.response_rules({}) == []


@pytest.mark.parametrize("value", ["train-ai=no", "train-ai", "train-ai=n\r\nX-Evil: 1", ""])
def test_invalid_content_usage_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="contentUsage"):
        signals.response_rules({"contentUsage": value})


def test_previous_ai_tokens_round_trip(robots: str) -> None:
    assert signals.previous_ai_tokens(robots) == ["CCBot", "GPTBot"]


def test_previous_ai_tokens_ignores_training_tokens_and_handles_missing_group() -> None:
    assert signals.previous_ai_tokens(signals.render_robots(CONFIG, [])) == []
    assert signals.previous_ai_tokens("") == []


def test_generated_files_carry_the_signals() -> None:
    cdn = yaml.safe_load((ROOT / "config" / "cdn.yaml").read_text())
    names = [r["name"] for r in cdn["data"]["responseTransformations"]["rules"]]
    assert names == ["set-content-usage-header"]
    assert cdn["data"]["trafficFilters"]["rules"]
    text = (ROOT / "config" / "robots.txt").read_text()
    assert can_crawl(text, "Googlebot", "/etc.clientlibs/x.css")
    assert can_crawl(text, "Amazonbot", "/content/site/en.html")
    assert not can_crawl(text, "Google-Extended", "/content/site/en.html")


def test_robots_groups_are_stable_and_case_insensitively_unique() -> None:
    forward = signals.render_robots(CONFIG, ["webzio-Extended", "Webzio-Extended", "CCBot"])
    backward = signals.render_robots(CONFIG, ["CCBot", "Webzio-Extended", "webzio-Extended"])
    assert forward == backward
    assert forward.lower().count("webzio-extended") == 1
