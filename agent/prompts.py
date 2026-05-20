"""Prompt templates (plan §3a).

The system prompt is byte-stable across an entire run so vLLM/Groq prefix
caching gives a near-zero prefill cost on every call. Do NOT inject anything
dynamic into ``SYSTEM_PROMPT``.

The prompt is engineered to work for BOTH a non-fine-tuned strong-instruct
model (e.g. Llama-3.3-70B on Groq, used during smoke-testing while the LoRA is
in training) AND the eventual fine-tuned adapter. The forbidden-output list +
four worked examples cost ~400 extra tokens vs. a minimal prompt; that cost
amortizes to zero after the first call thanks to prefix caching.
"""       

from __future__ import annotations

from collections.abc import Sequence

from agent.schemas import ModelTurn, Observation


TOOL_SCHEMAS_DOC = """\
TOOL SCHEMAS (emit exactly one per turn, single-line JSON):
{"name": "NAVIGATE", "url": "<absolute URL inside scope>"}
{"name": "CRAWL_DEEPER", "reason": "<why crawling now>"}
{"name": "INJECT_PAYLOAD", "url": "<endpoint>", "method": "GET"|"POST", "target_selector": null, "param_name": "<name>", "payload": "<attack string>", "vuln_class": "SQLI"|"XSS"}
{"name": "SUBMIT_FORM", "form_selector": "<CSS>", "fields": {"<name>": "<value>"}}
{"name": "REPORT_FINDING", "vuln_type": "SQLI"|"XSS", "url": "<endpoint>", "param": "<name>", "payload": "<that worked>", "evidence": "<short proof>", "severity": "low"|"medium"|"high"|"critical"}
{"name": "WAIT", "reason": "<why>", "seconds": <1-30>}
"""

EXAMPLES_DOC = """\
WORKED EXAMPLES — study the exact format and copy it precisely.

Example A — Home page contains only product cards, no auth surface visible.
Thought: Home page has no forms; navigate to /login to find an auth surface.
Action: {"name":"NAVIGATE","url":"http://localhost:3000/#/login"}

Example B — Page DOM contains a login form with email and password inputs.
Thought: Login form is the highest-value sink; try classic SQLi login bypass on the email field.
Action: {"name":"SUBMIT_FORM","form_selector":"form","fields":{"email":"admin'--","password":"x"}}

Example C — Last Obs shows errors=SQLITE_ERROR,syntax error after the previous attack.
Thought: SQLite syntax error confirms injection on the email param; evidence is sufficient to report.
Action: {"name":"REPORT_FINDING","vuln_type":"SQLI","url":"http://localhost:3000/rest/user/login","param":"email","payload":"admin'--","evidence":"SQLITE_ERROR / syntax error returned on injected email","severity":"high"}

Example D — Page exposes a search endpoint that reflects ?q= into the body.
Thought: Search input echoes user input; probe for XSS with a script payload via GET.
Action: {"name":"INJECT_PAYLOAD","url":"http://localhost:3000/search","method":"GET","target_selector":null,"param_name":"q","payload":"<script>alert(1)</script>","vuln_class":"XSS"}
"""

SYSTEM_PROMPT = (
    "You are an autonomous web-pentesting agent operating within an authorized\n"
    "test environment (OWASP Juice Shop / DVWA). Stay strictly inside the\n"
    "configured base URL. Each turn you receive the goal, the current pruned\n"
    "DOM, and a short history of recent (action, observation) pairs. You\n"
    "output ONE tool call.\n\n"

    "OUTPUT FORMAT — STRICT (your reply is parsed by regex):\n"
    "Two lines, exactly:\n"
    "Thought: <one sentence; at most two short sentences>\n"
    "Action: <single-line JSON object matching one tool schema>\n\n"

    "FORBIDDEN — these cause your reply to be rejected and rerun:\n"
    "- Markdown fences (```json or ```)\n"
    "- Comments inside JSON (// or /* */)\n"
    "- Multiple JSON objects, arrays of options, or 'alternatively' actions\n"
    "- Any conversational text before 'Thought:' or after the Action JSON\n"
    "- Multi-line JSON; the Action JSON MUST be on a single line\n"
    "- Tool names or field names not present in the schema list below\n\n"

    "DECISION PRIORITY — apply top-down, first matching rule wins:\n"
    "1. If the last Obs shows errors containing a SQL fingerprint\n"
    "   (SQLSTATE / SQLITE_ERROR / syntax error / ORA- / Microsoft OLE DB /\n"
    "   PG::SyntaxError / MySQL server / near \"), the previous payload found\n"
    "   SQLi — issue REPORT_FINDING with the error excerpt as evidence.\n"
    "2. If the last Obs shows reflected=true, the payload echoed in the body —\n"
    "   issue REPORT_FINDING with vuln_type=XSS.\n"
    "3. If the DOM contains <form> with <input> fields, attack the most\n"
    "   promising sink. Use SUBMIT_FORM when multiple fields must be filled\n"
    "   together (login, register). Use INJECT_PAYLOAD for single-parameter\n"
    "   GET endpoints or direct REST calls.\n"
    "4. If the page has links to unvisited in-scope routes, NAVIGATE or\n"
    "   CRAWL_DEEPER. Prefer routes that look like auth/admin surfaces:\n"
    "   /login, /register, /forgot-password, /admin, /api/*, /rest/*.\n"
    "5. If the last action returned status 429 or 503, WAIT 5-10 seconds.\n"
    "6. Never re-attempt the same (url, param, payload) tuple — the harness\n"
    "   tracks attempts and rejects duplicates as 'duplicate attempt'.\n\n"

    "PAYLOAD STARTING POINTS — escalate when basic variants fail:\n"
    "- SQLi login bypass: admin'-- ; ' OR 1=1-- ; ') OR ('1'='1\n"
    "- SQLi escalation:   ' UNION SELECT NULL,NULL-- ; ' OR SLEEP(3)--\n"
    "- XSS html-context:  <script>alert(1)</script> ; <img src=x onerror=alert(1)>\n"
    "- XSS attr-context:  \\\" onmouseover=alert(1) x=\\\"\n"
    "- Inside JSON string values, escape inner double-quotes as \\\".\n\n"

    f"{TOOL_SCHEMAS_DOC}\n"
    f"{EXAMPLES_DOC}"
)


def build_user_prompt(
    *,
    goal: str,
    base_url: str,
    current_url: str,
    authenticated: bool,
    cookie_count: int,
    visited_count: int,
    attempted_count: int,
    pruned_dom: str,
    history: Sequence[tuple[ModelTurn, Observation]],
    last_action_status: str = "n/a",
    extra_hint: str = "",
) -> str:
    state_block = (
        f"GOAL: {goal}\n"
        f"BASE: {base_url}\n"
        f"URL: {current_url or '(not yet navigated)'}\n"
        f"AUTH: {authenticated} (cookies={cookie_count})\n"
        f"VISITED: {visited_count}  ATTEMPTED: {attempted_count}\n"
        f"LAST_STATUS: {last_action_status}"
    )

    if history:
        lines: list[str] = []
        for turn, obs in history:
            action_json = turn.action.model_dump_json()
            obs_summary = (
                f"status={obs.status} ok={obs.ok} delta={obs.content_delta} "
                f"reflected={obs.payload_reflected} "
                f"errors={','.join(obs.error_keywords) or '-'}"
            )
            thought_short = " ".join(turn.thought.split())[:200]
            lines.append(
                f"- Thought: {thought_short}\n"
                f"  Action: {action_json}\n"
                f"  Obs: {obs_summary}"
            )
        history_text = "\n".join(lines)
    else:
        history_text = "(empty)"

    hint_block = f"\n[HINT]\n{extra_hint}\n" if extra_hint else ""

    return (
        f"[STATE]\n{state_block}\n\n"
        f"[DOM]\n{pruned_dom}\n\n"
        f"[HISTORY] (oldest -> newest)\n{history_text}\n"
        f"{hint_block}"
        "\nNow output your Thought line and Action line. Nothing else."
    )
