#!/usr/bin/env python3
"""Collect the translatable strings out of the management interface.

The interface is one hand-written HTML file with inline CSS and JavaScript and
no build step, so there is nothing to hook a conventional extraction pipeline
into. Translation therefore happens at the DOM level at runtime, keyed by the
Russian source string, and this script only has to produce the list of those
keys -- it never rewrites the markup.

Emits a JSON file: {"text": [...], "attr": {...}} where "text" holds the
strings that appear as text nodes and "attr" maps each translatable attribute
to the values found on it.
"""
import json
import re
import sys
from html.parser import HTMLParser

# Attributes whose value is shown to a person rather than consumed by code.
ATTRS = ("data-tip", "title", "placeholder", "aria-label", "alt")
SKIP_INSIDE = {"script", "style"}
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def normalise(s: str) -> str:
    """Collapse whitespace the way a browser does when rendering a text node."""
    return re.sub(r"\s+", " ", s).strip()


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.text: dict[str, int] = {}
        self.attr: dict[str, dict[str, int]] = {a: {} for a in ATTRS}

    def handle_starttag(self, tag, attrs):
        if tag not in ("br", "hr", "img", "input", "meta", "link"):
            self.stack.append(tag)
        for name, value in attrs:
            if name in self.attr and value and CYRILLIC.search(value):
                v = normalise(value)
                self.attr[name][v] = self.attr[name].get(v, 0) + 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass

    def handle_data(self, data):
        if SKIP_INSIDE & set(self.stack):
            return
        s = normalise(data)
        # Only strings with Cyrillic need translating; anything else is either
        # markup noise, a number, or already language-neutral.
        if s and CYRILLIC.search(s):
            self.text[s] = self.text.get(s, 0) + 1


# A ${...} substitution inside a template literal. Replaced by a sentinel so
# the surrounding markup still parses, and so that a text node containing one
# can be told apart from a fixed phrase.
SUBST = re.compile(r"\$\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}")
SENTINEL = "\x00"


# String literals of all three kinds. Backticks may carry substitutions;
# quoted literals may carry escapes. Both end up in the page as text, either as
# markup that is assigned to innerHTML or as a message shown to the user.
LITERALS = re.compile(
    r"`([^`]*)`"
    r"|'((?:[^'\\\n]|\\.)*)'"
    r'|"((?:[^"\\\n]|\\.)*)"'
)


def js_literals(html: str) -> list[str]:
    """Every string literal from inline <script> blocks, substitutions masked."""
    out = []
    for block in re.finditer(r"<script\b[^>]*>(.*?)</script>", html, re.S):
        for lit in LITERALS.finditer(block.group(1)):
            body = next((g for g in lit.groups() if g is not None), "")
            if body and CYRILLIC.search(body):
                # \n in a quoted literal is a newline once the page runs.
                body = body.replace("\\n", "\n").replace("\\t", "\t")
                out.append(SUBST.sub(SENTINEL, body))
    return out


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    html = open(src, encoding="utf-8").read()
    c = Collector()
    c.feed(html)
    static_text = dict(c.text)

    # Markup built in JavaScript reaches the page as ordinary text nodes, so the
    # runtime walker translates it too -- but only if the phrases are collected
    # here as well.
    d = Collector()
    for tpl in js_literals(html):
        d.feed(tpl)
        d.close()
        d.stack.clear()
    dynamic_text = {k: v for k, v in d.text.items() if k not in static_text}
    for a in ATTRS:
        for k, v in d.attr.get(a, {}).items():
            c.attr[a].setdefault(k, v)

    # Phrases carrying a substitution cannot be looked up whole; they are
    # reported separately so they can be handled explicitly in the runtime.
    interpolated = sorted(k for k in dynamic_text if SENTINEL in k)
    for k in interpolated:
        dynamic_text.pop(k)
    c.text.update(dynamic_text)

    payload = {
        "text": sorted(c.text),
        "attr": {a: sorted(v) for a, v in c.attr.items() if v},
        "interpolated": [k.replace(SENTINEL, "{}") for k in interpolated],
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")

    n_attr = sum(len(v) for v in payload["attr"].values())
    print(f"text nodes   : {len(payload['text']):4d} unique "
          f"({len(static_text)} static + {len(dynamic_text)} from scripts)")
    for a, v in payload["attr"].items():
        print(f"  {a:<12s}: {len(v):4d}")
    print(f"interpolated : {len(interpolated):4d}  (need explicit handling)")
    print(f"total keys   : {len(payload['text']) + n_attr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
