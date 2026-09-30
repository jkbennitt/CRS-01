# CRS-01 Security Audit — Source Recheck (source-only)

| Field | Value |
|-------|-------|
| **Target** | `jkbennitt/CRS-01` (fork of `0-CYBERDYNE-SYSTEMS-0/CRS-01`) |
| **Tree** | `main` @ `ebfb42d` (same commit as upstream `main`, verified via `git remote` + log) |
| **Date** | 2026-09-30 |
| **Method** | Local source read of this checkout. No application changes. No server, providers, archive.org, or other live network calls against the app. `.env` was not opened (not in tree). The seed KB and ingest ledger were not opened. No exploit payloads. |
| **Compared with** | `SECURITY-AUDIT-CLOUD.md` (PR #2, cloud pass) · Twodog source-only review (28 Sep 2026), SEC-01…SEC-07 + H-01 |

## Fork vs upstream

Fork `main` and upstream `main` are the same commit (`ebfb42d`). Every finding below was re-read against this tree, not carried forward on trust.

---

## 1. Alpha gate

The written model (`SECURITY.md` 11–19) is a single curator on loopback with provider keys in a gitignored `.env`. Source agrees with that model, and that model only:

- **Single curator, loopback only:** acceptable for a local alpha, with the integrity caveats below. No auth is the documented design.
- **Shared host, Tailscale-wide, or internet alpha:** does not pass. Every mutating route is unauthenticated (SEC-01), so any reachable client can spend provider budget, merge evidence, grant `VERIFIED`, quarantine or restore observations, materialize gated parents, edit aliases, persist Wayback hits, and purge the cache.
- **Local alpha that treats machine tiers as trustworthy:** does not pass yet. Two integrity defects fire with no remote attacker: errored runs still mutate the KB (SEC-02), and LLM lineage rows are bound to a result URL without checking the claimed text occurs in that result (SEC-03). Hostile page text in a search snippet is sufficient.

---

## 2. Re-verification of prior findings

All prior IDs hold at `ebfb42d`. Cites are this tree's current lines.

| ID | Status | Evidence (file:line) | Notes |
|----|--------|---------------------|-------|
| **SEC-01** unauthenticated writes | **Confirmed** | `backend/src/main.py:33-54` (no auth middleware or `Depends`); writes: `research.py:42-96`, `curation.py:64-99, 102-125, 136-159, 162-177`, `archive.py:66-84`, `neighborhood.py:130-133`; design statement `SECURITY.md:11-13`; `dev.sh:39` (uvicorn, no `--host`), `dev.sh:43` (`next dev`, no `-H`) | Loopback-friendly defaults are not ACL once proxied. See N-02 for the default-exposure refinement. |
| **SEC-02** failed run still merged | **Confirmed** | `research.py:54-68` (merge runs before the `run.error` check; merge exceptions swallowed "non-fatal" at 66-68), `research.py:92-94` (error → HTTP 200); `orchestrator.py:370-372` (`run.error = str(e)` — `run()` swallows everything), 373-388 (ledger still appended); `kb.py:1036-1209` (merge never consults `error`), 1063-1064 (sources), 1128-1136 (observations), 1163-1166 (subject `_touch` even with zero claims), 1195-1206 (`record_run`), 1208 (`recompute()` regardless) | Ledger-on-failure remains intentional; the KB mutation is the defect. Empty failure still upserts the subject strain. |
| **SEC-03** LLM claims not grounded in cited text | **Confirmed** | `llm_extractor.py:30-31, 100-108` (prompt stops at 14k chars / 2400 per result) vs `llm_extractor.py:141-151` (index validated against the FULL `results` list); `llm_extractor.py:168-177` (`snippet_excerpt` = the model's `evidence` string — no containment check), 179-184 (metadata equally ungrounded); regex path is span-based (`extractor.py:238`); `providers.py:265-276` (Perplexity citations become index targets with empty snippets) | Gap is LLM-only; the regex extractor slices the actual match. |
| **SEC-04** path/error disclosure | **Confirmed** | `research.py:111` (`ledger_path` in the by-strain response), `research.py:58` (`detail=f"research failed: {e}"`); `orchestrator.py:102-103, 295-297, 372` (`raw_dir`, `error=str(e)` in every submit response); `curation.py:119-123, 154-157, 172-175` (raw `str(e)` as detail) | |
| **SEC-05** non-atomic restore, no member checks | **Confirmed** | `scripts/restore_kb.sh:20-22` (`rm -rf backend/data/raw` first), 24-25 (in-place `tar -xzf`, no staging/allowlist/checksum); `scripts/snapshot_kb.sh:13-15` (unsanitized `LABEL` in output path), 42-62 (manifest has sizes/counts, no hashes) | "Writes outside `backend/data`" stays **unproven** — see §4. |
| **SEC-06** host-less URLs count as "domains"; Wayback URL stored unscheme-checked | **Confirmed** | `agreement.py:66-67` (synthesized → None), 71-72 (`return url.lower() or None` when no hostname), 73-78 (`.lower()` only, no IDNA fold); archive talks only to the fixed host `archive.org/wayback/available` with the URL as a param (`ingestion/archive.py:34-35, 76-80`); `wayback_url` = the JSON `closest.url`, stored with no scheme check (`ingestion/archive.py:88`, `routes/archive.py:53-58`, `kb.py:518-529`) | Archive is a fixed-host availability proxy, not classic SSRF; it never fetches the caller's URL. |
| **SEC-07** no rate limit / resource growth / event-loop block | **Confirmed** | No rate limiter anywhere in `main.py` or route deps; `research.py:43-55` (sync `orchestrator.run` on an async route — blocks the loop; 45s LLM timeout `llm_extractor.py:191`, `time.sleep` on 429 `providers.py:381-395`); `research.py:100` (by-strain `limit` uncapped; full-file scan `ledger.py:43-63`); `kb.py:2339-2345` (`search_strains` reads every strain row); `kb.py:2399-2419` (`stats` reads all strain rows); `provider_cache.py:166-199` (expired rows deleted only when that key is read again) | `pending_parents` IS clamped ≤ 500 inside the KB (`kb.py:2155`) — that queue is bounded. |
| **H-01** unfiltered `href`s; partial `isHttpSource` | **Confirmed** | No `dangerouslySetInnerHTML` anywhere in `frontend/src`. Guarded: `ReportView.tsx:373-375` (`isHttpSource`), 432-449 (provenance card links), 390-396 + 501 (`providerLabel` renders non-http schemes as plain text), 547 + 768-787 (summary attribution gated). Unguarded: `SourcesView.tsx:119-130`, `NodeDetailCard.tsx:189-201, 231-247, 515-528`, `ConflictsPanel.tsx:316-323`, `ResearchingPanel.tsx:190-203`, `ReportView.tsx:504-508` (card Wayback link) + 1133-1140 (deepen claims) | React escapes attribute injection; the live vector is a stored non-http(s) scheme reaching an anchor. Not a stored-XSS finding as-is. |

### Cloud-pass additions (C-01…C-09) — all still true

| ID | Status | Evidence |
|----|--------|----------|
| C-01 event-loop blocking | Confirmed | Same call site as SEC-07: `research.py:42-55`. One in-flight research stalls reads and other writes on a single worker. |
| C-02 `VERIFIED` stamps carry no curator id | Confirmed | `curation.py:35-38` (no identity field in `ReviewRequest`); `kb.py:1836-1840` (tier, free-text note, timestamp only). The route docstring (`curation.py:66-71`) promises attributability to "a person" but records no person. |
| C-03 `CRS_LLM_BASE_URL` receives the OpenAI bearer | Confirmed | `llm_extractor.py:81-85` (base URL from env, default `api.openai.com/v1`), 219-224 (bearer posted to that host). Operator/env-controlled, not request-controlled. `next.config.ts:3, 10-15` (`BACKEND_ORIGIN` rewrite). |
| C-04 Next sets no security headers | Confirmed | `frontend/next.config.ts:5-16` (no `headers()`); `layout.tsx` sets no CSP (only a static inline `<style>` at line 51). |
| C-05 OpenAPI/docs exposed | Confirmed | `main.py:33-37` (default docs on), 69-76 (root advertises `/docs`). The Next rewrite does not proxy `/docs`. |
| C-06 CORS `allow_credentials=True` + wildcard methods/headers | Confirmed | `main.py:39-46`; origins default to exact localhost list (`config.py:40`). No cookie session exists. |
| C-07 seed KB + ledger tracked in git | Confirmed | `git ls-files backend/data` → `crs01.db`, `ingest_ledger.jsonl` (contents not opened). `provider_cache.db` ignored. Only `.env.example` tracked — no `.env` in tree. |
| C-08 unauthenticated `POST /graph/cache/purge` | Confirmed | `neighborhood.py:130-133`. Clears the in-process map only; no data loss. |
| C-09 no client-controlled filesystem paths | Confirmed | Slugs are normalized SQL keys (`kb.py:292-293`); `raw_dir` is a server-generated uuid path (`orchestrator.py:295-297`); no route accepts a client `raw_dir`. |

---

## 3. New this pass

| ID | Severity | Evidence | Impact |
|----|----------|----------|--------|
| **N-01** neighborhood cache grows unbounded with lazy expiry | Low | `neighborhood.py:44-70` — `_CACHE` is keyed (slug, depth 0-3) with no size cap; an expired entry is removed only when that same key is read again (59-61); it is cleared only when some write path calls `purge_cache()`. | Same growth class as the provider cache noted under SEC-07, but on the API read path. Bounded in practice by KB size; minor. |
| **N-02** default `dev.sh` exposure is wider than "uvicorn stays on loopback" | Info (exposure refinement to SEC-01) | `dev.sh:39` launches uvicorn with no `--host` (uvicorn's documented default is 127.0.0.1), but `dev.sh:43` launches `next dev` with no `-H` (Next's documented default binds all interfaces), and `next.config.ts:10-15` proxies `/api/v1/:path*` to the backend. | With the stock script alone, the unauthenticated write API is reachable from the LAN through the frontend port — no explicit proxy needed. Both bind claims are from tool documentation; not runtime-tested (source-only). |

No finding IDs were renumbered or contradicted; I do not disagree with the prior pass on any ID.

---

## 4. Softened / unproven (kept soft)

- **Hostile tarball "writes outside `backend/data`"** — controls are indeed absent (no staging, allowlist, or checksum in `restore_kb.sh`), but whether the host `tar` extracts `..` members was not tested. Keep Twodog's wording; do not upgrade.
- **Browser handling of non-http(s) `href` values** — no browser run; no payloads.
- **Whether archive.org's `closest.url` can ever be a non-archive, non-https value** — the field is stored as returned; live answers were not requested.

## 5. Negatives re-confirmed

- **No SQL injection.** Every value query binds with `?`; dynamic `IN (...)` clauses interpolate only `?` placeholders (`kb.py:1399, 1472, 1586, 1734, 2135`); the one interpolated `LIMIT` is a computed `int` (`kb.py:1465-1474`), not a client string; `PRAGMA`/`ALTER TABLE` identifiers come from in-code migration constants (`kb.py:186-210`).
- **No secrets in API responses.** Provider keys are read from env into `Authorization` headers only (`providers.py:119-121, 217-221`; `llm_extractor.py:219-224`); `/graph/stats` returns token counts, not keys (`kb.py:2413-2438`). Whether an httpx exception string could ever echo a header into a log was not observed live (see §6).
- **No `dangerouslySetInnerHTML` / `innerHTML`** anywhere in `frontend/src`.
- **No client-controlled filesystem paths** (C-09 above).
- **`/archive/wayback` still answers 501** (`routes/archive.py:87-102`) — no fabricated submission path.

## 6. Explicitly unverified

| Item | Why |
|------|-----|
| Live binds, TLS, firewalls, proxies, Tailscale | Source-only; processes were not started. Bind claims in N-02 are from uvicorn/Next documentation. |
| Runtime `.env` values (`CORS_ORIGINS`, `CRS_LLM_BASE_URL`, `BACKEND_ORIGIN`, keys) on any deployed host | Env files not read; no `.env` in tree. |
| Contents of tracked `crs01.db` / `ingest_ledger.jsonl` | Tracked, but not opened. |
| Whether host `tar` follows `..` members in `restore_kb.sh` | No archive built or extracted. |
| Browser treatment of non-http scheme `href`s | No browser run. |
| Dependency CVEs (FastAPI, httpx, Next, React) | No SCA tool; CI runs pytest + lint/build only. |
| SQLite behavior under multiple uvicorn workers | Not load-tested; connections are short-lived by design (`kb.py` docstring 39-41). |
| Whether httpx exception text can echo an `Authorization` header into `run.error`/logs | Failures are caught and logged (`providers.py:133-135`; `llm_extractor.py:232-234`); no live error was captured. |
| IDNA/punycode folding behavior on sample hosts | Not executed; source shows `.lower()` only (`agreement.py:64-78`). |

## 7. Scope

**Read:** `backend/src/main.py`, `config.py`, all `api/routes/*.py`, `graph/kb.py` (full), `graph/agreement.py`, `ingestion/archive.py`, `ingestion/ledger.py`, `ingestion/research/{orchestrator, providers, llm_extractor, extractor, wikipedia_full, provider_cache}.py`, `frontend/next.config.ts`, `frontend/src/app/layout.tsx`, `frontend/src/lib/api-client.ts`, all link-rendering components (`ReportView`, `NodeDetailCard`, `SourcesView`, `ConflictsPanel`, `ResearchingPanel`), `scripts/{restore,snapshot}_kb.sh`, `dev.sh`, `SECURITY.md`, `git ls-files`/`.gitignore` for tracked data, and the prior `SECURITY-AUDIT-CLOUD.md` (PR #2 branch) for ID alignment.

**Not done:** running the app or tests (docs-only change), provider/archive.org calls, opening `.env` or the seed DB, writing exploits, changing application code.
