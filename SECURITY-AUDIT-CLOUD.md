# CRS-01 Cloud Security Audit (source-only)

| Field | Value |
|-------|-------|
| **Target** | https://github.com/jkbennitt/CRS-01 (fork of `0-CYBERDYNE-SYSTEMS-0/CRS-01`) |
| **Tree** | `main` @ `ebfb42d2e941a782bfee4bc4ea7f3ef6e24f2cfa` (2026-09-28) |
| **Date** | 2026-09-29 |
| **Method** | Local source read of this checkout. No application changes. No providers, archive.org, or other live network calls. `.env` was not opened (it is not in the tree). The seed KB and ingest ledger were not opened. No exploit payloads. |
| **Compared with** | Twodog HTML review “CRS-01 · Security Review” (28 Sep 2026) and `crs01-security-audit.md` (independent review of upstream `main` at the same SHA) |

## Fork vs upstream

`jkbennitt/CRS-01` `main` and `0-CYBERDYNE-SYSTEMS-0/CRS-01` `main` are the **same commit** (`ebfb42d`). Security-relevant paths (`backend/src/**`, `frontend/src/**`, `scripts/restore_kb.sh`, `scripts/snapshot_kb.sh`, `SECURITY.md`, `frontend/next.config.ts`) are not ahead or behind upstream. The attached markdown audit reviewed this exact tree. Twodog’s line citations match this tree.

---

## 1. Executive summary and alpha release gate

CRS-01 is a FastAPI + Next.js lineage tool whose `SECURITY.md` says the API has **no authentication by design** and must stay on a trusted network. Source confirms that: every mutating route is mounted with no auth dependency, and FastAPI’s default `/docs`, `/redoc`, and `/openapi.json` stay on. `./dev.sh` starts uvicorn **without** `--host`, so the script itself does not publish the backend on all interfaces. That default is loopback-friendly. It is not an access control once a reverse proxy, `BACKEND_ORIGIN`, or an explicit bind is added. The Next rewrite in `frontend/next.config.ts` forwards `/api/v1/*` to the backend, so publishing only the frontend still publishes the write API.

**Alpha release gate**

| Use | Gate |
|-----|------|
| Single curator, loopback only, as `SECURITY.md` describes | **Acceptable** for a local alpha, with the integrity caveats below. Lack of app auth is the documented design. |
| Shared host, Tailscale-wide, or internet alpha | **Does not pass.** Untrusted clients can submit research (provider spend + KB writes), set `VERIFIED`, quarantine evidence, resolve gated parents, edit aliases, persist Wayback hits, and purge the neighborhood cache. |
| Local alpha that treats machine tiers as trustworthy | **Does not pass yet.** Two integrity bugs fire without a remote attacker: an errored research run is still merged, and LLM lineage rows are bound to a result URL without a check that the claimed text appears in that result. Hostile page text in a search snippet is enough. |

Highest-priority code defects, independent of exposure:

1. `POST /research/submit` always calls `kb.merge_research_run` after `orchestrator.run`, including when `run.error` is set. The ledger append on failure is intentional (`SPEC` / `test_failed_run_appends_ledger_row`). The KB mutation is the defect. Orchestrator exceptions are swallowed inside `run()`, so the client usually sees **HTTP 200** with `run.error` populated, after the merge.
2. `llm_extractor._parse_response` checks `source_index` bounds and copies that result’s URL. It does not require the model’s `evidence` or parent names to occur in that result’s title/snippet. The prompt builder also stops at 14,000 characters while the parser still accepts indexes into the full result list.
3. `registrable_domain()` returns the raw lowercased string when a URL has no hostname, so non-HTTP strings can each count as an independent “domain” toward `COMMUNITY_CONSENSUS`.

Twodog SEC-01..SEC-07 and H-01 are **confirmed** on this tree, with the refinements in §4. The attached markdown audit is also confirmed, including its extra items (OpenAPI, CORS+credentials, tracked seed data, Next rewrite, unauthenticated cache purge). This pass adds: event-loop blocking on the research route, subject-strain upsert on an empty failed merge, the HTTP 200 failure path, missing curator identity, unvalidated stored Wayback URLs, config-controlled LLM base URL, and the absence of response security headers.

---

## 2. Strengths

- **Threat model is written down.** `SECURITY.md` lines 11–13: no auth, local/trusted network, do not expose the ports.
- **`VERIFIED` is human-only.** `claim_tier()` (`backend/src/ingestion/research/orchestrator.py` 132–152) returns only `CONTRADICTED`, `COMMUNITY_CONSENSUS`, or `ANECDOTAL`. `set_curated_tier` is the stamp (`backend/src/graph/kb.py` 1803–1843). `CURATABLE_TIERS` is `VERIFIED`, `COMMUNITY_CONSENSUS`, `ANECDOTAL` (`kb.py` 1773). `CONTRADICTED` is rejected on the review route (`curation.py` 79–86).
- **Unresolved parents stay gated.** `merge_research_run` does not materialize an unknown parent as a node (`kb.py` 1051–1054, 1119–1145, 1190–1193).
- **Synthesized provider answers do not count as domains.** `tavily://` and `perplexity://` return `None` from `registrable_domain` (`agreement.py` 26–30, 66–67).
- **Confidence does not gate writes.** Tiers are the trust system; confidence is stored and displayed.
- **Regex extraction is text-anchored.** `extract_lineage` builds `snippet_excerpt` from the matched span of the result text (`extractor.py` 238–259). The grounding gap is the LLM path.
- **SQLite value queries use placeholders.** Surveyed `execute` sites bind user-derived values with `?`. Dynamic `IN (...)` clauses interpolate only `?` placeholders. The one interpolated `LIMIT` is `int(remaining)` with `remaining` computed as `24 - len(claim_rows)` (`kb.py` 1465–1474), not a client string. `PRAGMA` / `ALTER TABLE` identifiers come from in-code migration specs (`kb.py` 186–210).
- **Wayback fails open and does not fetch the caller’s URL.** `wayback_availability` GETs the fixed host `https://archive.org/wayback/available` with the URL as a query parameter and never raises (`archive.py` 34–35, 68–99). Autolookup defaults off (`config.py` 35–37). `POST /archive/wayback` returns 501 (`routes/archive.py` 87–101).
- **Wikipedia fetches stay on `en.wikipedia.org`.** Full text uses `action=parse` with `page` as a parameter (`wikipedia_full.py` 182–194). The orchestrator derives the title from a result URL that already contains `/wiki/` (`orchestrator.py` 583–594).
- **Provider keys are not hardcoded and are not response fields.** `.env` is gitignored. `.env.example` uses a placeholder. Keys are read from the environment into `Authorization` headers (`providers.py` 119–121, 217–221; `llm_extractor.py` 219–224). `/graph/stats` returns token **counts** (`kb.py` 2413–2438), not secrets. A tree search for live key prefixes found only the placeholder pattern in `PUBLISHING.md`.
- **Per-request research bounds exist.** Query length 1–200, `max_depth` ≤ 3, `max_nodes` ≤ 100 (`research.py` 31–34). Several list routes use `Query(..., le=...)`.
- **No `dangerouslySetInnerHTML` / `innerHTML` in the frontend.** Dossier nav links are in-page hashes built in code (`ReportView.tsx` 693–704), not API URLs. Provenance cards filter source links with `isHttpSource` (`ReportView.tsx` 373–375, 432–449).
- **Search lead images are no longer attached to strains** (`kb.py` 418–436). No `<img src>` bindings were found in `frontend/src`.
- **Ledger append on failure is deliberate and tested** (`orchestrator.py` 360–388; `backend/tests/test_ledger_accounting.py` 44–63).

---

## 3. Findings

Severity: **Critical** (untrusted client can change trust or spend budget) · **High** · **Medium** · **Low** · **Info**. “Critical” applies when the API is reachable by an untrusted client. On a loopback single-curator host, SEC-01 is the documented design (Info).

| ID | Severity | Evidence | Impact | High-level fix |
|----|----------|----------|--------|----------------|
| **SEC-01** | Critical if exposed; Info on loopback | No auth middleware or `Depends` in `backend/src/main.py` 33–54. Writes: `research.py` 42–94; `curation.py` 64–174 (`review`, quarantine, resolve, aliases); `archive.py` 66–84; `neighborhood.py` 130–133. `SECURITY.md` 11–13 states the design. `dev.sh` 38–39 does not pass `--host`. | Anyone who can reach the port can burn provider budget, merge evidence, grant `VERIFIED`, quarantine rows, materialize gated parents, and purge the in-process cache. | Keep the process off untrusted networks. For a shared alpha, put an operator-controlled access check on mutating routes (proxy auth or a shared secret). Document that “no auth” and a public alpha cannot both be true. |
| **SEC-02** | High (local integrity) | `research.py` 62–94 merges `run.to_dict()` before the `if run.error` return, and that return is still HTTP 200. `orchestrator.run` sets `run.error` and still returns the partial object (`orchestrator.py` 370–388). `merge_research_run` (`kb.py` 1036–1209) does not consult `error`. It upserts `sources_visited` (1063–1064), writes observations (1128–1136), and always `_touch`es the query string (1163–1166) and `record_run` (1195–1206). `test_failed_run_merges_into_kb_with_error` (`test_ledger_accounting.py` 110–126) locks the “errored dict still merges” behavior for the run row. The outer `HTTPException(500)` at `research.py` 56–58 does not run for exceptions `run()` already caught. Per-provider failures are logged and do **not** set `run.error` (`orchestrator.py` 444–447). | A stage exception after claims exist persists those claims and can move a tier. A failure with zero claims still creates or refreshes the subject strain and a `research_runs` row. Callers see success-shaped HTTP with an error field. | Keep the ledger append. Skip `merge_research_run` when `run.error` is set, or merge only the `research_runs` audit row and leave observations untouched. |
| **SEC-03** | High when an LLM key is set; otherwise dormant | Prompt includes title/snippet and stops at `_MAX_TOTAL_CHARS` (`llm_extractor.py` 30–31, 100–108). `_parse_response` (123–177) checks index range, non-empty URL, and clamps confidence. `snippet_excerpt` is the model’s `evidence` string. Metadata keys are copied if they are short strings (179–184) and stored on the subject (`orchestrator.py` 518–526). Perplexity citation rows can have an empty snippet (`providers.py` 265–276) and remain valid indexes. | A model can attribute parent names and an excerpt to a real URL that does not contain them. Two such rows on different registrable domains can satisfy the consensus count. Metadata (summary, THC, breeder) has the same gap. | Accept a row only when the evidence span and parent tokens occur in that result’s title/snippet, and only for indexes actually included in the prompt. Drop or demote the rest. Keep regex extraction, which already slices the match. |
| **SEC-04** | Medium | `GET /research/by-strain` returns `ledger_path` (`research.py` 107–112; path resolver `ledger.py` 19–26). `ResearchRun.to_dict` includes `raw_dir` and `error` (`orchestrator.py` 88–106, 295–297). `run.error` is `str(e)` (`orchestrator.py` 372). The 500 detail string also interpolates the exception (`research.py` 58) on the narrower path that escapes `run()`. Curation `ValueError` / `KeyError` text is returned as `detail` (`curation.py` 119–123, 154–157, 172–174). | Host layout and parser/DB/provider exception text leave the process. Aids reconnaissance. Provider handlers log failures internally and generally do not place keys in these fields; that last point was not proven by reading a live error. | Return generic client errors. Log server-side. Omit `ledger_path` and `raw_dir` from JSON. |
| **SEC-05** | Medium (operator) | `restore_kb.sh` 17–25 deletes `backend/data/raw` then `tar -xzf` into `backend/data` with no staging directory, member allowlist, or checksum. `snapshot_kb.sh` 13–15 puts the unsanitized `[label]` argument into the output path. The manifest records sizes and counts, not hashes (42–62). No HTTP restore route exists. | An interrupted restore can drop `raw/` and leave the DB, ledger, and raw files on different timelines. A hostile archive’s ability to write outside `backend/data` depends on the host `tar` and was **not** tested. A label containing `..` can aim the snapshot file outside `snapshots/` when an operator passes it. | Extract to a temp directory, reject members that escape the dest root, then replace `crs01.db`, the ledger, and `raw/` as a unit. Sanitize the snapshot label to a single path segment. Add hashes to the manifest. |
| **SEC-06** | Medium | `registrable_domain` (`agreement.py` 54–78): synthesized schemes return `None`; otherwise a missing hostname returns `url.lower()`. No IDNA / punycode fold (only `.lower()`). Consensus uses that set (`orchestrator.py` 772–784; KB recompute imports the same helper). `POST /archive/lookup` forwards any non-empty string to archive.org and, on a hit, inserts it (`routes/archive.py` 43–64; `kb.set_source_archive` 504–528). `wayback_url` from the JSON body is stored with no scheme or host check. | Distinct non-HTTP strings can each count as a voice and promote `COMMUNITY_CONSENSUS`. Unicode and punycode spellings of one host can count twice because the code never normalizes them. The archive route is an unauthenticated availability proxy plus a conditional KB insert, not a fetch of the caller’s URL. A stored `wayback_url` is later rendered as `href` (see H-01). | Return `None` unless the scheme is `http` or `https` and the host is a real registrable name; fold IDNA to one key. Allowlist archive lookup inputs to `http(s)`. Persist `wayback_url` only when its host is the archive’s. |
| **SEC-07** | Medium if exposed | No rate limiter or concurrency cap in `main.py` or route dependencies. `research_submit` is `async` but calls blocking `orchestrator.run` (`research.py` 54–55`), which uses synchronous `httpx` and `time.sleep` on Wikipedia 429s (`providers.py` 381–394). Defaults are depth 2 and 30 nodes (`research.py` 49–52) with provider timeouts up to 45s (`providers.py` 206, `llm_extractor.py` 191). Each run appends the ledger and writes `raw/<run_id>/`. `GET /research/by-strain` `limit` has no `Query` maximum and the reader scans the whole file before slicing (`research.py` 99–112; `ledger.py` 42–64). `search_strains` loads every strain row (`kb.py` 2339–2345) even though the route caps returned matches at 20. Provider-cache TTL deletes an expired row only when that key is read again (`provider_cache.py` 166–199). `pending_parents` does clamp to 500 (`kb.py` 2155). | One research call can occupy the worker and spend provider quota. Repeated unique queries grow the ledger, raw dumps, SQLite, and the provider cache. Large ledgers make by-strain reads proportional to file size. | Rate-limit `POST /research/submit`. Run the pipeline off the event loop. Cap `by-strain` `limit`. Page or bound the search scan. Evict expired cache rows on a schedule. |
| **H-01** | Medium (link scheme); not a stored-XSS finding | No `dangerouslySetInnerHTML`. Unfiltered `href` from KB/API strings: `SourcesView.tsx` 119–130; `NodeDetailCard.tsx` 189–201, 231–233, 515–526; `ConflictsPanel.tsx` 316–323; `ResearchingPanel.tsx` 190–203; deepen card `ReportView.tsx` 1133–1140. Provenance cards allow only `^https?://` (`ReportView.tsx` 373–375, 432–449) and render other schemes as text (499–502). Wayback links on those cards are **not** passed through `isHttpSource` (504–506). In-page dossier hashes are safe (693–704). Summary attribution is gated by `isHttpSource` (547, 778–779). | If a non-HTTP URL is stored, a click can navigate to that scheme. React text nodes stay escaped. Browser handling of specific schemes was not executed. | One shared allowlist for every API-fed `href`, including Wayback URLs: `https` (and `http` if still required), optionally pinned to `web.archive.org` for archive links. |

### Additional items (this pass)

| ID | Severity | Evidence | Impact | High-level fix |
|----|----------|----------|--------|----------------|
| **C-01** | Medium if exposed | Same as SEC-07’s blocking call: `async def research_submit` invokes sync `orchestrator.run` on the event loop (`research.py` 42–55). | With one worker, one in-flight research stalls health, reads, and other writes. | `asyncio.to_thread` or a worker queue, plus a concurrency cap. |
| **C-02** | Low | `set_curated_tier` stores tier, note, and timestamp only (`kb.py` 1836–1840). No actor column. Review body has no identity field (`curation.py` 35–38). | A `VERIFIED` stamp is not attributable to a person once more than one operator can hit the route. Matches the single-curator story; it does not survive a shared alpha. | Record an operator id supplied by the access check from SEC-01. |
| **C-03** | Low (config) | OpenAI-compatible extraction posts the bearer token to `CRS_LLM_BASE_URL` (default `https://api.openai.com/v1`) (`llm_extractor.py` 72–85, 219–224). Perplexity, when its key is set, uses a fixed host. Next proxies `/api/v1/:path*` to `BACKEND_ORIGIN` (`next.config.ts` 3–14). | An operator-controlled (or environment-injected) base URL receives the provider key, or turns the Next server into a proxy for that origin. This is not a request-chosen SSRF. | Pin LLM base URL in production, or allowlist hosts. Treat `BACKEND_ORIGIN` as a secret-equivalent deploy setting. |
| **C-04** | Info | `frontend/next.config.ts` has no `headers()`. `layout.tsx` sets no CSP. | No browser policy backs the React escaping. Relevant if H-01 links or a future HTML sink regress. | Add a tight CSP and baseline security headers at the proxy or in Next. |
| **C-05** | Info | `FastAPI()` uses default docs (`main.py` 33–37). Root advertises `"docs": "/docs"` (69–76). | Anonymous clients get the full route map when the backend port is reachable. The Next rewrite does not proxy `/docs`. | Disable `docs_url`, `redoc_url`, and `openapi_url` except on local dev. |
| **C-06** | Info (misconfig) | `CORSMiddleware` uses `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]` (`main.py` 39–46). Defaults are localhost origins (`config.py` 40`). `.env.example` 29 is the same shape. The app has no cookie session. | Defaults are exact localhost origins. A later wildcard or broad list combined with credentials would let browsers call the unauthenticated writes cross-origin. Same-origin rewrites avoid CORS when `NEXT_PUBLIC_API_URL` is unset (`api-client.ts` 19–23). | Set the alpha origin list explicitly. Leave credentials off until a cookie session exists. |
| **C-07** | Info | `backend/data/crs01.db` and `backend/data/ingest_ledger.jsonl` are tracked (`.gitignore` 45–47 comments this as intentional). Contents were not opened. | Public seed evidence: queries, URLs, excerpts, run metadata. Not a key leak from this review. | Decide whether the seed ledger’s size and content belong in a public fork. |
| **C-08** | Info | `POST /graph/cache/purge` (`neighborhood.py` 130–133) clears only the in-process neighborhood map. | Forces recomputation. No data loss. | Remove it from the public app or fold it under the same access check as other writes. |
| **C-09** | Info (negative) | Slugs are `normalize_slug` (whitespace to hyphen, lowercased) and used as SQL keys (`kb.py` 292–293), not filesystem paths. `raw_dir` is a server-side `uuid` under the ledger parent (`orchestrator.py` 295–297). The HTTP API does not accept a client `raw_dir`. | Request path traversal into the data directory was not found on the route surface. | Keep it that way. If `merge_research_run` is ever called with an external dict, treat `raw_dir` as untrusted. |

---

## 4. Comparison to prior reviews

### Twodog SEC-01..SEC-07 and H-01

| Twodog ID | Verdict on this fork | Notes |
|-----------|----------------------|-------|
| **SEC-01** Unauthenticated writes | **Confirm** | All mutating handlers lack an auth dependency. Severity stays conditional on reachability. `dev.sh` does not set `--host 0.0.0.0`; that lowers the *default script* exposure and was not called out in the HTML. It does not close the finding once a proxy is added. |
| **SEC-02** Failed run still merged | **Confirm and extend** | Merge-before-error-check is real. Ledger-on-failure is specified and tested; the defect is KB mutation (claims, sources, and a subject upsert even when claims are empty). Clients get HTTP 200 because `run()` swallows the exception. The 500 branch is a second, narrower path. |
| **SEC-03** LLM URL index, no span check | **Confirm** | Twodog’s extra detail holds: the parser validates against the full `results` list after the prompt stops at the character cap (`llm_extractor.py` 105–106 vs 146). Metadata is ungrounded too. Regex extraction is span-based; the gap is LLM-only. Perplexity citations can be indexed with an empty snippet. |
| **SEC-04** Path and error disclosure | **Confirm** | `ledger_path`, `raw_dir`, and `run.error` are the live disclosure. The `research failed: {e}` 500 is present and rarely reached for orchestrator failures. |
| **SEC-05** Non-atomic restore | **Confirm** | `rm -rf raw` then in-place `tar`. Twodog’s caution is right: member traversal was not executed, so arbitrary write outside the dest is unverified. This pass adds the unsanitized snapshot label path. |
| **SEC-06** Domain count as independence | **Confirm** | Hand-maintained suffix list, no IDNA, no citation-ancestry collapse. Host-less fallback (`agreement.py` 71–72) is the concrete consensus-gaming edge. Wayback is a fixed-host parameter proxy plus a hit insert, which the HTML described accurately. Stored `wayback_url` is not scheme-checked. |
| **SEC-07** Resource growth | **Confirm and extend** | No rate limit; cache expiry is lazy; by-strain scans the ledger with no route cap. `pending_parents` is clamped at 500, so that queue is bounded. New: the research handler blocks the event loop (C-01), and strain search reads the full table. |
| **H-01** Shared scheme allowlist | **Confirm; not XSS** | No HTML sink. `isHttpSource` covers provenance source URLs and the summary link. It does not cover Sources, node detail, conflicts, the researching panel, the deepen card, or Wayback `href`s. Browser scheme behavior was not run. |

Twodog items this pass also agrees were **absent**: no cancel/retry route, `/archive/wayback` is 501, no user-controlled URL is fetched by archive or Wikipedia code, no static mount of `.env` or the KB, no SQL injection in value queries, no key field in API payloads.

### Attached markdown audit (`crs01-security-audit.md`)

That audit targeted upstream `ebfb42d`, which **is** this fork’s `main`. Its SEC-01..07 and H-01 verdicts match the code. Its N-01..N-08 are confirmed here as C-05, C-06, C-07, the Next rewrite (still true: `next.config.ts` 10–14), C-08, and the three negatives (keys not in responses, no SQLi found, slug ≠ path).

| Markdown claim | This pass |
|----------------|-----------|
| Failed runs always merge | **Confirm**, with the HTTP 200 and subject-upsert refinements above. |
| LLM claims are not span-checked | **Confirm**. The markdown report understated the prompt-cap vs full-list index gap that twodog already had. |
| `registrable_domain` host-less fallback | **Confirm** (`agreement.py` 71–72). |
| Open Wayback proxy, not classic SSRF | **Confirm**. Destination is fixed. |
| Tar slip “can write outside `backend/data`” | **Soften.** Controls are missing. Exploitability was not tested and is host-`tar`-dependent. Twodog’s wording is the one to keep. |
| No `dangerouslySetInnerHTML`; partial `isHttpSource` | **Confirm.** Deepen card (`ReportView.tsx` 1133–1140) is an extra unfiltered `href`. |
| OpenAPI, CORS credentials, tracked seed, rewrite, cache purge | **Confirm.** |
| N-06 keys not in API responses | **Confirm** from source. Live responses were not captured. |

**Neither prior review stated clearly:** event-loop blocking (C-01); empty failed merges still upsert the subject; curator identity is absent (twodog’s diagram mentioned it, the finding list did not); `wayback_url` is stored unsanitized; `CRS_LLM_BASE_URL` receives the OpenAI key; `dev.sh` omits `--host`; regex extraction is the grounded path; `pending_parents` is capped inside the KB.

---

## 5. Prioritized fix order for an alpha

Assume the alpha might be more than one trusted laptop. Integrity items matter even on loopback.

1. **Write boundary (SEC-01, Next rewrite).** Do not publish the backend or the `/api/v1` rewrite to untrusted clients. If the alpha is shared, require an operator check on every `POST` before any other code change.
2. **Stop KB mutation on `run.error` (SEC-02).** Still append the ledger row. Do not upsert observations, sources, or the subject strain for a failed run.
3. **Scrub disclosure (SEC-04).** Drop `ledger_path` and `raw_dir` from responses. Generic HTTP errors; log the exception server-side.
4. **Docs and CORS (C-05, C-06).** Turn off `/docs`, `/redoc`, and `/openapi.json` outside local dev. Pin `CORS_ORIGINS` to the real frontend origins. Prefer the same-origin rewrite and leave `NEXT_PUBLIC_API_URL` unset.
5. **Cost and availability (SEC-07, C-01).** Rate-limit and cap concurrency on `POST /research/submit`. Move `orchestrator.run` off the event loop. Cap `by-strain` `limit`.
6. **Link allowlist (H-01).** Use one `http(s)` helper for every API-fed `href`, and allow archive links only on the archive host.
7. **LLM grounding (SEC-03).** Require the excerpt and parent tokens to appear in the cited result text, and only for indexes included in the prompt.
8. **Domain function (SEC-06).** Count only `http(s)` registrable domains; fold IDNA; ignore host-less strings. Restrict archive lookup inputs the same way.
9. **Restore (SEC-05).** Stage, check member paths, then replace. Sanitize the snapshot label. Hash the manifest.
10. **Then:** curator identity (C-02), pull cache purge behind the write boundary (C-08), security headers (C-04), pin `CRS_LLM_BASE_URL` (C-03).

---

## 6. Explicitly unverified

| Item | Why |
|------|-----|
| Live bind, TLS, firewall, Tailscale, reverse proxy | Source-only. `dev.sh` flags were read; the process was not started. |
| Contents of `.env`, `CORS_ORIGINS`, `NEXT_PUBLIC_API_URL`, `CRS_LLM_BASE_URL`, `BACKEND_ORIGIN` on any deployed host | Env files were not read. No `.env` is in this checkout. |
| Contents of tracked `crs01.db` and `ingest_ledger.jsonl` (PII, unexpected secrets) | Files are tracked; they were not opened. |
| Browser treatment of non-HTTP `href` values | No browser run, no payloads. |
| Whether `tar` on a given host extracts `..` members from `restore_kb.sh` | Code order only. No archive was built or extracted. |
| Dependency CVEs (FastAPI, httpx, Next, React) | No SCA tool. CI (`.github/workflows/ci.yml`) runs pytest and frontend lint/build only. |
| SQLite behavior under multiple uvicorn workers | Not load-tested. Connections are short-lived by design (`kb.connect`). |
| Private-history repo (`PUBLISHING.md`) | Out of scope. That document says it must stay private. |
| Whether archive.org’s `closest.url` is always an archive HTTPS URL | Response field is stored as returned (`archive.py` 88–95). Live answers were not requested. |
| IDNA output of `registrable_domain` on sample hosts | Not executed. Source shows `.lower()` and no IDNA encode (`agreement.py` 64–78). |
| Whether an `httpx` exception string can echo an `Authorization` header into a log line | Provider and LLM failures are caught and logged (`providers.py` 133–135; `llm_extractor.py` 232–234). Log text was not captured. |
| Redirect following on DuckDuckGo (`follow_redirects=True`, `providers.py` 322–327) | Fixed initial host. Where that host redirects was not observed. |
| Effectiveness of a future CSP | No header is set today (C-04). |

---

## 7. Scope

**Read:** `backend/src/main.py`, `config.py`, `api/routes/*.py`, `graph/kb.py`, `graph/agreement.py`, `ingestion/archive.py`, `ingestion/ledger.py`, `ingestion/research/{orchestrator,providers,llm_extractor,extractor,wikipedia_full,provider_cache}.py`, `frontend/src/lib/api-client.ts`, `frontend/next.config.ts`, `frontend/src/app/layout.tsx`, link-rendering components (`SourcesView`, `ReportView`, `NodeDetailCard`, `ConflictsPanel`, `ResearchingPanel`), `scripts/{restore,snapshot}_kb.sh`, `dev.sh`, `SECURITY.md`, `.env.example`, `.gitignore`, `PUBLISHING.md`, `.github/workflows/ci.yml`, and the failure-ledger test.

**Not done:** running the app, pytest, providers, archive.org, reading `.env` or the seed database, writing exploits, or changing application code.
