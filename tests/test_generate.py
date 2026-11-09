"""Tests for robots.txt writing when the AI crawler feed is unavailable."""
from pathlib import Path

import generate
import signals

CFG = {"contentUsage": "train-ai=n", "sitemaps": ["https://www.example.com/sitemap.xml"]}


def test_outage_keeps_ai_tokens_but_applies_config_changes(tmp_path: Path) -> None:
    path = tmp_path / "robots.txt"
    path.write_text(signals.render_robots({"contentUsage": "train-ai=n"}, ["GPTBot"]))
    notes: list[str] = []
    assert generate.write_robots(path, CFG, [], True, notes) is True
    text = path.read_text()
    assert "User-agent: GPTBot\n" in text
    assert "Sitemap: https://www.example.com/sitemap.xml\n" in text
    assert any("kept the previous AI crawler list" in n for n in notes)


def test_outage_without_previous_file_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "robots.txt"
    notes: list[str] = []
    generate.write_robots(path, CFG, [], True, notes)
    assert "User-agent: *" in path.read_text()
    assert any("WARNING" in n for n in notes)


def test_healthy_feed_replaces_tokens_and_reports_no_change_when_identical(tmp_path: Path) -> None:
    path = tmp_path / "robots.txt"
    assert generate.write_robots(path, CFG, ["GPTBot"], False, []) is True
    assert generate.write_robots(path, CFG, ["GPTBot"], False, []) is False
    assert generate.write_robots(path, CFG, ["CCBot"], False, []) is True
    assert "GPTBot" not in path.read_text()
