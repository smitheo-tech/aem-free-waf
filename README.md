# aem-free-waf

A self-updating, **licence-free alternative to Adobe's WAF traffic filter rules** for
AEM as a Cloud Service.

It generates `config/cdn.yaml` using only **standard traffic filter rules**: no `wafFlags`,
so the Extended Security / WAF-DDoS Protection add-on isn't needed. The rules are rebuilt
every day from maintained open-source threat data:

| Source | What it gives | Licence |
|---|---|---|
| [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset), latest v4 release | Scanner user agents, restricted files, OS file and LFI lists, shell, PowerShell, Java class and SSRF lists, plus ~70 ported regex rules (traversal, SQLi, XSS, RCE, RFI, protocol attacks, Java/Log4j) | Apache-2.0 |
| [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) | ~930 datacenter/hosting ASNs, used for a tighter per-IP rate limit | MIT |
| [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) (optional) | ~1.2k Tor exit IPs | – |
| [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) | ~200 AI crawlers and agents, classified by purpose | MIT |
| Vendor IP lists: Google (refreshed daily), Bing, OpenAI, Perplexity, Apple, Anthropic, Mistral | Catch impostors: a UA that claims to be a bot from an IP that isn't the vendor's | – |
| `base-rules.yaml` (hand-maintained) | AEM-specific hardening: `/bin/querybuilder`, `.infinity.json`, `/system/console`, PHP/WordPress probes, rate limits, Adobe's starter rules | – |

## How it stays up to date

```
GitHub Action (daily 03:17 UTC)
  └─ generator/generate.py   pull latest CRS tag + feeds → convert → fit into 100 KB
  └─ tests/run_tests.py      attacks must hit, legit AEM URLs must not be blocked
  └─ open/update a PR        body = build report (sources, versions, size, skipped)
You merge → Cloud Manager config pipeline deploys config/cdn.yaml
```

The PR is only opened when the generated rules actually change (for example a new CRS
release or new ASNs). Merging stays a human step, so a bad upstream change can't reach
prod on its own.

## Coverage compared with Adobe's WAF flags

| Adobe WAF flag | Free equivalent here |
|---|---|
| SQLI, XSS, CMDEXE, CODEINJECTION, TRAVERSAL, LOG4J-JNDI | CRS regex rules, on the URL and query string |
| USERAGENT, SCANNER | CRS `scanners-user-agents.data` |
| PRIVATEFILE, BACKDOOR | CRS `restricted-files.data` and AEM foreign-tech probes |
| RESPONSESPLIT, BHH, NULLBYTE, DOUBLEENCODING, NOUA, NO-CONTENT-TYPE | CRS 921 rules and base header rules |
| OOB-DOMAIN | Base rule |
| DATACENTER | Rate limit on X4BNet ASNs, with search bots excluded |
| TORNODE | Optional Tor exit list |
| SANS, BAD-IP, ATTACK-FROM-BAD-IP | Partly: the error-burst rate limit catches scanners by behaviour |
| JSON-ERROR, XML-ERROR, MALFORMED-DATA, COMPRESSED (body), CVE virtual patches | **Not possible.** The CDN can't inspect request bodies |

Detection rate against SecLists payloads sent in a query parameter, measured offline at build time:
XSS 99%, command injection 100%, LFI 87%, SQLi 70%. Most SQLi misses are bare keywords
such as `update` or `like`, which aren't attacks.

## Bots, crawlers, scanners and AI agents

| Traffic | Identified by | Default |
|---|---|---|
| Attack scanners (sqlmap, nuclei, nikto...) | CRS scanner UA list | **block** |
| Fake Googlebot / Bingbot / GPTBot / ClaudeBot... | UA claims the bot, IP isn't in the vendor's published ranges | log → flip to block |
| AI training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider, meta-externalagent...) | ai.robots.txt, category `ai-training` | **block** |
| AI search crawlers (OAI-SearchBot, Claude-SearchBot, PerplexityBot) | ai.robots.txt `ai-search` | allowed, so you stay visible in AI answers |
| AI assistants fetching for a user (ChatGPT-User, Claude-User, Perplexity-User) | ai.robots.txt `ai-assistants` | allowed |
| AI agents and browser agents | ai.robots.txt `ai-agents` | log |
| AI data resellers and others | ai.robots.txt | rate limit |
| Signed agents (ChatGPT agent, Google agent, via Web Bot Auth) | `Signature-Agent` header | log (presence only, see below) |
| HTTP libraries and headless browsers (python-requests, Go, curl, HeadlessChrome...) | UA list in `waf-config.yaml` | rate limit, counted only |
| Any other self-declared bot or crawler | Generic "bot/crawl/spider" pattern, verified vendors excluded | rate limit → block |
| Real search engines (Googlebot, Bingbot...) | Not touched; excluded from every bot rate limit | – |

Change any of this in `bots.aiPolicy` / `bots.aiOverrides` in `waf-config.yaml`. An override of
`allow` removes a bot from the AI rules only: if its UA says bot or crawler and its vendor isn't
verified, the generic crawler rate limit still applies.

## robots.txt and AI usage signals

The generator writes a complete `config/robots.txt` from the `robots:` section of
`waf-config.yaml`, so polite crawlers stop on their own while the CDN enforces the policy for
the rest:

| Part | What it does |
|---|---|
| `User-agent: *` group | AEM crawl hygiene (`/bin/`, `/libs/`, search and filter parameters), keeps `/etc.clientlibs/` open |
| `Content-Signal: search=yes, ai-input=yes, ai-train=no` | Cloudflare Content Signals preference |
| `Content-Usage: train-ai=n` | IETF AIPREF preference, also sent as a response header on publish |
| `Google-Extended`, `Applebot-Extended` | Training-only tokens, closed without affecting search visibility |
| `__usage_ai-training` | Policy token for a site-wide training opt-out |
| Named AI crawler groups | Every bot the CDN policy blocks. Rate-limited bots stay crawlable, because refusing them would remove the site from services such as Brave Search |
| EU DSM Art. 4(3) comment | States the text and data mining rights reservation; have the client's counsel confirm the wording |

A few limits to keep in mind:
- Content-Signal and Content-Usage are preferences, not access control, and both Content-Usage
  drafts are still changing. Google has said it ignores Content-Signal.
- Set `robots.sitemaps` per site, and adjust `disallowQueryParams` to the site's parameters.
  A blocked URL can't show a crawler its `noindex`, so don't block parameters on URLs you're
  actively removing from the index.
- If ai.robots.txt can't be fetched, its previous crawler list is kept and config edits still apply.

Design rules:
- **Nothing identified by User-Agent ever gets `allow`.** `allow` skips every other rule, and
  a UA is trivial to fake. "Allowed" AI bots simply have no rule.
- **An impostor rule is only emitted when all of that vendor's IP lists were fetched.** A
  partial list would block the real bot. If a source is down, the previous build's rule is
  kept, so PRs don't flap.
- **Impostor rules start on `log`.** Switch them to `block` once the daily PR gets merged
  promptly; a stale list (a new Googlebot range) would otherwise block the real Googlebot.

What the CDN **can't** do: run JavaScript or CAPTCHA challenges, fingerprint TLS (JA3/JA4) or
cryptographically verify Web Bot Auth signatures. AI agents driving a real browser with a
normal UA and no signature look like humans at this layer. Adobe's CDN has no challenge
action, so only behavioural rate limits catch those.

## Setup

1. Copy this folder into your AEM project repository, or keep it as its own repo and point
   `--out` at the AEM repo's `config/cdn.yaml`.
2. Edit `waf-config.yaml`: environments, allowlisted IPs, and whether Tor blocking is on.
3. Run it locally once:
   ```bash
   pip install -r requirements.txt
   python generator/generate.py && python tests/run_tests.py
   ```
4. Create a Cloud Manager **config pipeline** for `config/`, and deploy to **dev** first.
5. Publish `config/robots.txt` as the robots.txt your site serves. That's often a DAM asset
   or a dispatcher rule; a CDN rule can't serve it. Merge in anything site-specific that's
   in your current file.
6. Enable the GitHub Action. It needs the repo setting
   *Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"*.
   If Cloud Manager builds from Adobe's own git repo rather than GitHub, add a mirror step
   (there's an example in the workflow).

## Verify once on dev (important)

Adobe's docs call `urlRaw`/`pathRaw` the "unescaped" variants, and the generator matches on
those because the CRS regexes expect decoded input. Confirm it with one request:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<dev-publish>/content/x.html?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

- **406** (or your status) means decoding works as expected and you're done.
- **200** means swap `decodedPathProperty: path` and `decodedUrlProperty: url` in
  `waf-config.yaml`, then regenerate.

Then confirm the file with both sections deployed and that the response header arrives. Adobe's
docs describe `trafficFilters` and `responseTransformations` as top-level sections but never show
them in one sample:

```bash
curl -sI "https://<dev-publish>/content/x.html" | grep -i content-usage   # content-usage: train-ai=n
```

## Rollout

- Shipped as **block**: scanner user agents, restricted files, path traversal, AEM
  sensitive paths, foreign-tech probes, Log4j headers, null byte and OOB domains. These have
  a very low false-positive rate.
- Shipped as **log**: SQLi, XSS, RCE, RFI, LFI lists and the protocol rules. Watch the CDN
  logs for 1–2 weeks, using Adobe's ELK/Splunk traffic-filter dashboards, then switch each
  rule to `block` in `waf-config.yaml`.
- For every false positive you find, add the URL to `tests/samples.yaml` under `legit`.
  CI then guarantees it never gets blocked again.

## Tuning

- Size: `cdn.yaml` must stay under 100 KB. Sections are added in `priority` order, and
  anything that doesn't fit is listed as *skipped* in the PR. Currently it's ~98 KB with all vendor impostor rules, so enabling Tor (~25–35 KB) would push out the lowest-priority sections.
- To add or remove CRS rules, edit `crsRegexRules` (CRS rule IDs). PHP (933) and Node.js
  (934) families are left out on purpose because AEM is Java.
- To pin a CRS version, set `crsRef: v4.30.0`.

## Limitations, honestly

- There's no request body inspection, apart from Adobe's `postParam`, which only reads named
  form fields. Attacks sent in JSON or XML POST bodies are not covered.
- There's no IP-reputation feed comparable to Adobe's or Fastly's. CRS uses anomaly scoring
  and libinjection, and this port uses plain regex matches, so it's a strong filter for
  automated attacks, not a full replacement for a commercial WAF on high-risk apps.
- The regexes are tested with Python's engine; the CDN uses Fastly's PCRE. Always deploy to
  dev first.
