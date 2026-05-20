"""HTML pruner — reduces a raw page DOM to security-relevant compact form.

Plan §3b rules: drop scripts/styles/comments, keep forms/inputs/links and
elements with on*= handlers, truncate long text nodes, dedupe sibling runs,
annotate forms with index comments and reflected inputs with markers.
Hard token cap enforced by ``prune_with_cap``.

Also strips Angular Material / SPA wrapper tags (mat-*, app-*, router-outlet)
so the model — trained on simple PHP/MySQL-style HTML — can see the inputs
and buttons that are otherwise buried in component shells. Emits an explicit
ATTACK_SURFACE comment block at the top listing every sink it found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

# Tags whose entire subtree is dropped (heavy noise / no security value).
DROP_TAGS = frozenset({"script", "style", "noscript", "svg", "canvas", "video", "audio"})

# Pure-decoration Angular Material tags — drop subtree entirely (no inputs inside).
ANGULAR_DECORATION_TAGS = frozenset({
    "mat-icon", "mat-divider", "mat-hint", "mat-error", "mat-label",
    "mat-slider-visual-thumb", "mat-progress-spinner", "mat-spinner",
    "mat-mdc-hint",
})

# Structural Angular wrappers — unwrap (keep children, drop the wrapper tag itself).
# Reduces nesting noise without losing the inputs / buttons they contain.
ANGULAR_STRUCTURAL_TAGS = frozenset({
    "mat-toolbar", "mat-toolbar-row",
    "mat-sidenav", "mat-sidenav-container", "mat-sidenav-content",
    "mat-card", "mat-card-content", "mat-card-actions",
    "mat-form-field", "mat-mdc-form-field",
    "mat-menu", "mat-nav-list", "mat-list", "mat-list-item",
    "mat-grid-list", "mat-grid-tile",
    "mat-paginator", "mat-select", "mat-checkbox", "mat-radio-group", "mat-radio-button",
    "mat-slider", "mat-tab-group", "mat-tab", "mat-expansion-panel",
    "mat-dialog-container", "mat-dialog-content", "mat-option",
    "app-mat-search-bar", "app-navbar", "app-server-started-notification",
    "app-ctf-system-wide-notification", "app-challenge-solved-notification",
    "app-welcome", "app-search-result", "app-welcome-banner",
    "router-outlet", "app-root", "sidenav", "mat-icon-button",
})

# Semantic Angular components we KEEP (their name tells the model what page it's on).
# Examples: app-login, app-register, app-contact, app-administration, etc.

# Attributes worth keeping because they can be vulnerability sinks or control points.
SINK_ATTRS = frozenset({
    "action", "formaction", "src", "href", "value", "name", "id", "type",
    "method", "enctype", "placeholder", "target", "rel",
})

EVENT_HANDLER_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")
TEXT_TRUNCATE = 80
TEXT_MAX = 100
SIBLING_DEDUPE = 5


@dataclass
class PrunedDom:
    html: str
    form_count: int
    link_count: int
    input_count: int

    def header_line(self) -> str:
        return (
            f"<!-- INDEX forms={self.form_count} "
            f"links={self.link_count} inputs={self.input_count} -->"
        )

    def render(self) -> str:
        return f"{self.header_line()}\n{self.html}"


def _is_keep_attr(name: str) -> bool:
    if name in SINK_ATTRS:
        return True
    if name.startswith("data-"):
        return True
    if EVENT_HANDLER_RE.match(name):
        return True
    return False


def _filter_attrs(tag: Tag) -> None:
    drop = [k for k in tag.attrs if not _is_keep_attr(k)]
    for k in drop:
        del tag.attrs[k]


def _truncate_text_nodes(soup: BeautifulSoup) -> None:
    for node in list(soup.find_all(string=True)):
        if isinstance(node, Comment):
            continue
        raw = str(node)
        collapsed = WHITESPACE_RE.sub(" ", raw).strip()
        if not collapsed:
            node.replace_with("")
            continue
        if len(collapsed) > TEXT_MAX:
            collapsed = collapsed[:TEXT_TRUNCATE] + "..."
        node.replace_with(collapsed)


def _reflected_param_names(url: str) -> set[str]:
    if not url:
        return set()
    try:
        return set(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return set()


def _annotate_forms(soup: BeautifulSoup) -> int:
    count = 0
    for idx, form in enumerate(soup.find_all("form")):
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        form.insert(0, Comment(f" form#{idx} action={action!r} method={method} "))
        count += 1
    return count


def _annotate_reflected_inputs(soup: BeautifulSoup, reflected: set[str]) -> None:
    if not reflected:
        return
    for inp in soup.find_all(["input", "textarea"]):
        n = inp.get("name", "")
        if n and n in reflected:
            inp.insert_before(Comment(" REFLECTED "))


def _dedupe_sibling_runs(soup: BeautifulSoup) -> None:
    """Collapse runs of >SIBLING_DEDUPE same-tag siblings to first 3 + comment."""
    for parent in soup.find_all(True):
        children = [c for c in parent.children if isinstance(c, Tag)]
        i = 0
        while i < len(children):
            run_tag = children[i].name
            run_start = i
            while i < len(children) and children[i].name == run_tag:
                i += 1
            run_len = i - run_start
            if run_len > SIBLING_DEDUPE:
                placeholder = Comment(f" {run_len - 3} more {run_tag} elided ")
                children[run_start + 2].insert_after(placeholder)
                for victim in children[run_start + 3 : i]:
                    victim.decompose()
                children = [c for c in parent.children if isinstance(c, Tag)]
                i = run_start + 4
            else:
                i = run_start + run_len


def _strip_angular_noise(soup: BeautifulSoup) -> None:
    """Drop pure-decoration mat-* tags and unwrap structural mat-*/app-* wrappers."""
    # Drop decoration entirely (mat-icon, mat-divider, etc.)
    for tag_name in ANGULAR_DECORATION_TAGS:
        for t in soup.find_all(tag_name):
            t.decompose()
    # Unwrap structural wrappers — keep children
    for tag_name in ANGULAR_STRUCTURAL_TAGS:
        for t in soup.find_all(tag_name):
            t.unwrap()


def _collapse_empty_wrappers(soup: BeautifulSoup) -> None:
    """Aggressively drop <div>/<span> that have no attributes, no sink descendants, and no text."""
    sink_tags = {"input", "textarea", "select", "button", "form", "a", "iframe", "img"}
    # Run multiple passes — each pass may expose newly-empty wrappers.
    for _ in range(4):
        changed = False
        for tag in list(soup.find_all(["div", "span"])):
            if tag.attrs:
                continue
            if tag.find(sink_tags):
                continue
            if tag.get_text(strip=True):
                continue
            tag.decompose()
            changed = True
        if not changed:
            break


def _summarize_attack_surface(soup: BeautifulSoup, max_items: int = 30) -> str:
    """Build an ATTACK_SURFACE comment block listing every input/button/form-like sink.

    Each sink line shows id/name/type/href and the nearest semantic container
    (app-* component or <form>). This lets the model attack Angular SPAs without
    a real <form> element.
    """
    lines: list[str] = []

    def nearest_container(tag: Tag) -> str:
        for parent in tag.parents:
            if not isinstance(parent, Tag):
                continue
            name = parent.name or ""
            if name == "form":
                return "form"
            if name.startswith("app-") and name not in ANGULAR_STRUCTURAL_TAGS:
                return name
        return ""

    def attr_str(tag: Tag, *keys: str) -> str:
        bits = []
        for k in keys:
            v = tag.get(k)
            if v:
                bits.append(f"{k}={str(v)[:50]!r}")
        return " ".join(bits)

    count = 0

    # Forms (rare in Angular SPAs but always interesting if present)
    for form in soup.find_all("form"):
        if count >= max_items:
            break
        info = attr_str(form, "id", "action", "method")
        lines.append(f"form {info}".strip())
        count += 1

    # Inputs / textareas
    for inp in soup.find_all(["input", "textarea"]):
        if count >= max_items:
            break
        info = attr_str(inp, "id", "name", "type", "placeholder", "value")
        ctx = nearest_container(inp)
        ctx_part = f" container={ctx}" if ctx else ""
        lines.append(f"{inp.name} {info}{ctx_part}".strip())
        count += 1

    # Submit-like buttons
    for btn in soup.find_all("button"):
        if count >= max_items:
            break
        btn_type = (btn.get("type") or "").lower()
        btn_id = (btn.get("id") or "").lower()
        if btn_type != "submit" and "submit" not in btn_id and "login" not in btn_id:
            continue
        info = attr_str(btn, "id", "type")
        ctx = nearest_container(btn)
        ctx_part = f" container={ctx}" if ctx else ""
        lines.append(f"button {info}{ctx_part}".strip())
        count += 1

    if not lines:
        return ""

    body = "\n".join(f"<!--   {ln} -->" for ln in lines)
    return f"<!-- ATTACK_SURFACE -->\n{body}\n<!-- /ATTACK_SURFACE -->"


def prune(html: str, page_url: str = "") -> PrunedDom:
    soup = BeautifulSoup(html, "html.parser")

    for c in list(soup.find_all(string=lambda s: isinstance(s, Comment))):
        c.extract()
    for tag_name in DROP_TAGS:
        for t in soup.find_all(tag_name):
            t.decompose()
    for link in soup.find_all("link"):
        link.decompose()
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        if name not in {"csrf-token", "viewport"}:
            meta.decompose()

    for t in soup.find_all(True):
        _filter_attrs(t)

    # Strip Angular SPA noise BEFORE text truncation / dedupe so those
    # operations work on a much smaller tree.
    _strip_angular_noise(soup)
    _collapse_empty_wrappers(soup)

    _truncate_text_nodes(soup)
    form_count = _annotate_forms(soup)
    _annotate_reflected_inputs(soup, _reflected_param_names(page_url))
    _dedupe_sibling_runs(soup)

    input_count = len(soup.find_all(["input", "textarea", "select"]))
    link_count = len(soup.find_all("a"))

    # Build the attack-surface summary AFTER cleaning so containers reflect
    # the final structure the model sees.
    attack_surface = _summarize_attack_surface(soup)

    body = WHITESPACE_RE.sub(" ", str(soup)).strip()
    rendered = f"{attack_surface}\n{body}" if attack_surface else body

    return PrunedDom(
        html=rendered,
        form_count=form_count,
        link_count=link_count,
        input_count=input_count,
    )


def estimate_tokens(s: str) -> int:
    """Rough token estimate (~4 chars/token; conservative)."""
    return max(1, len(s) // 4)


def prune_with_cap(html: str, page_url: str = "", max_tokens: int = 1500) -> PrunedDom:
    """Prune; if rendered output exceeds the token cap, hard-truncate.

    The hard truncation preserves the index header so the model still sees form
    and link counts even when the body is clipped.
    """
    pruned = prune(html, page_url)
    rendered = pruned.render()
    if estimate_tokens(rendered) <= max_tokens:
        return pruned

    char_budget = max_tokens * 4
    header = pruned.header_line()
    body_budget = max(0, char_budget - len(header) - len("\n<!-- TRUNCATED -->"))
    truncated_html = pruned.html[:body_budget] + "<!-- TRUNCATED -->"
    return PrunedDom(
        html=truncated_html,
        form_count=pruned.form_count,
        link_count=pruned.link_count,
        input_count=pruned.input_count,
    )
