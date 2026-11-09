# aem-free-waf – context for Claude Code

A free, self-updating alternative to the licensed AEM WAF rules (Extended Security / WAF-DDoS)
for AEM as a Cloud Service. It generates `config/cdn.yaml` from **standard traffic filter
rules only** (never `wafFlags`), from upstream sources rebuilt daily by a GitHub Action.

## Layout
- `waf-config.yaml` – all settings: actions (log/block), CRS rule IDs, bot/AI policy, priorities, size budget
- `base-rules.yaml` – hand-maintained AEM-specific rules (querybuilder, .infinity.json, PHP probes, rate limits, Adobe starter rules)
- `generator/generate.py` – fetches OWASP CRS (latest v4 tag via `git ls-remote`), X4BNet ASNs, Tor; converts; fits under 100 KB by priority
- `generator/bots.py` – ai.robots.txt policy by purpose, vendor IP impostor detection, generic crawler/HTTP-lib rate limits, Web Bot Auth logging, returns the robots.txt tokens
- `generator/signals.py` – full `config/robots.txt` and the `Content-Usage` response header rule, from `robots:` in `waf-config.yaml`
- `tests/run_tests.py` + `tests/samples.yaml` – offline evaluator; attacks must hit, legit AEM URLs must not be blocked
- `tests/test_bots.py`, `tests/test_signals.py`, `tests/test_generate.py` – pytest unit tests (classification, robots.txt crawl policy, header rule)
- `tests/bench_seclists.py` – detection rate vs SecLists payloads
- `.github/workflows/update-waf.yml` – daily regenerate → test → PR

## Commands
```bash
pip install -r requirements.txt
python generator/generate.py --cache .cache   # build (cache = offline reruns)
python tests/run_tests.py                     # must be 0 failures
pip install pytest && python -m pytest tests -q
python tests/bench_seclists.py                # optional detection benchmark
```

## Key decisions (don't undo without asking)
- Adobe docs call `urlRaw`/`pathRaw` the *unescaped* variants → CRS regexes match those (configurable). Verify on a dev env with the curl test in the README.
- CRS regexes are rewritten: `(?i)`, `^`/`$` → argument-boundary anchors, `\s` also matches `+`, ARGS rules scoped to the query part (`\?.*?`).
- PHP (933) and Node (934) CRS families excluded; huge 932 unix-command regexes excluded (size). SQLi adds selected PL2 rules (libinjection isn't portable).
- Never `allow` anything identified by User-Agent (spoofable; `allow` skips all rules).
- Vendor impostor rule only emitted if ALL of that vendor's IP lists fetched; on fetch failure the previous build's rule is kept (no flapping PRs). Impostor rules default to `log`.
- robots.txt: preferences and hygiene live in the `*` group, because a crawler obeys only its most specific group. `/etc.clientlibs/` stays open (rendering). `Google-Extended`/`Applebot-Extended` get `allow` for the CDN (never sent as UA) but are closed in robots.txt (their only control). Only `block` bots get `Disallow: /`; rate-limited bots stay crawlable.
- Priority: attack rules first, then bot rules, then large low-value lists (lfi/unix/powershell).
- Generated output must be byte-identical between runs, or the daily Action opens empty PRs. Upstream has names differing only by case, so sort on a total key.
- Risky rules ship as `log`; flip to `block` in `waf-config.yaml` after 1–2 weeks of clean CDN logs.
- Licence: Apache-2.0, open source (decided 2026-11-09). Copyright holder in NOTICE: "Smitheo".
- Wording: "alternative to the licensed WAF rules", never "Adobe WAF for free" or "equivalent". Upstream licences live in `NOTICE` (checked 2026-11-09); only X4BNet's MIT ASN list is used, never its CC BY-SA IP ranges.

