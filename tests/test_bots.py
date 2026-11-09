"""Unit tests for AI-bot classification and robots.txt token handling in generator/bots.py."""
import json

import bots
import pytest


@pytest.mark.parametrize(
    ("function", "expected"),
    [
        ("AI tools and models for machine learning research.", "ai-training"),  # LAIONDownloader
        ("AI research crawler", "ai-other"),  # Poseidon: 'research' is not search
        ("Search result generation.", "ai-search"),
        ("AI Search Crawlers", "ai-search"),
        ("Takes action based on user prompts.", "ai-assistants"),  # MistralAI-User/1.0
        ("Collects data for AI natural language search", "ai-search"),
        ("Scrapes data.", "ai-training"),
        ("LLM/AI training.", "ai-training"),
    ],
)
def test_classify(function: str, expected: str) -> None:
    assert bots.classify(function) == expected


@pytest.mark.parametrize(
    ("name", "token"),
    [
        ("GPTBot", "GPTBot"),
        ("Brightbot 1.0", "Brightbot"),
        ("panscient.com", "panscient"),
        ("iaskspider/2.0", "iaskspider"),
        ("meta-externalagent", "meta-externalagent"),
    ],
)
def test_robots_token_keeps_leading_product_token(name: str, token: str) -> None:
    assert bots.robots_token(name) == token


def _build(robots_json: dict, overrides: dict | None = None) -> tuple:
    cfg = {
        "actions": {},
        "bots": {
            "genericCrawlerRateLimit": False,
            "logSignedAgents": False,
            "aiPolicy": {"ai-training": "block", "ai-other": "ratelimit", "ai-search": "allow"},
            "aiOverrides": overrides or {},
        },
    }
    return bots.build(lambda _url: json.dumps(robots_json), cfg, [])


def test_build_returns_tokens_for_blocked_bots_only() -> None:
    data = {
        "BlockMe": {"function": "LLM training."},
        "Limit Me 1.0": {"function": "Something else."},
        "SearchMe": {"function": "AI Search Crawlers"},
        "Overridden": {"function": "LLM training."},
        "__usage_ai-training": {"function": "AI Data Scrapers"},
    }
    sections, _origin, tokens, failed = _build(data, {"Overridden": "allow"})
    assert tokens == ["BlockMe"]  # "Limit Me 1.0" stays crawlable: rate limited, not refused
    assert failed == set()
    assert "bots-ai-block" in sections


def test_build_treats_empty_ai_list_as_failure() -> None:
    _sections, _origin, tokens, failed = _build({})
    assert tokens == []
    assert "bots-ai-block" in failed


def test_build_reports_failure_when_ai_list_unreachable() -> None:
    def boom(_url: str) -> str:
        raise OSError("down")

    cfg = {"actions": {}, "bots": {"genericCrawlerRateLimit": False, "logSignedAgents": False}}
    _sections, _origin, tokens, failed = bots.build(boom, cfg, [])
    assert tokens == []
    assert "bots-ai-block" in failed


def test_token_regex_is_stable_and_case_insensitively_unique() -> None:
    forward = bots.token_regex(["Meta-ExternalAgent", "meta-externalagent", "GPTBot"])
    backward = bots.token_regex(["GPTBot", "meta-externalagent", "Meta-ExternalAgent"])
    assert forward == backward
    assert forward.lower().count("externalagent") == 1
