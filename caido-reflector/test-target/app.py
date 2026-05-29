"""
Vulnerable test target for caido-reflector.

Original context routes:
  /body, /attr_dq, /attr_sq, /attr_unq, /js_dq, /js_sq, /js_tpl, /js_code,
  /href, /comment, /css, /safe

POST sinks:
  /post (form), /json

Blacklist / filter routes (added to exercise the aggressive probe):
  /bl_lt_gt        — drops `<` and `>` only
  /bl_quotes       — drops `"` and `'`
  /bl_script_kw    — strips the literal word `script`
  /htmlentity_only — HTML-entity encodes `<` and `>` only (quotes unchanged)
  /js_escape_dq    — backslash-escapes `"` only, leaves `'` and `` ` `` alone
  /href_bl_js      — removes the literal `javascript:` scheme but allows `data:`
  /strip_xss       — strips `<>"'` (allows backtick and backslash)
  /url_encode_all  — URL-encodes every character (correct defense)

WARNING: Intentionally vulnerable. Run on 127.0.0.1 only.
"""
from urllib.parse import quote

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


# ───────── index ─────────

@app.get("/")
def index():
    return (
        "<h1>Reflector test target</h1>"
        "<p>See README.md for the full route list.</p>"
    )


# ───────── context routes ─────────

@app.get("/body")
def body():
    return f"<html><body><p>Hello {request.args.get('q','')}</p></body></html>"


@app.get("/attr_dq")
def attr_dq():
    return f'<html><body><input value="{request.args.get("q","")}"></body></html>'


@app.get("/attr_sq")
def attr_sq():
    return f"<html><body><input value='{request.args.get('q','')}'></body></html>"


@app.get("/attr_unq")
def attr_unq():
    return f"<html><body><input value={request.args.get('q','')}></body></html>"


@app.get("/js_dq")
def js_dq():
    return f'<html><body><script>var v = "{request.args.get("q","")}";</script></body></html>'


@app.get("/js_sq")
def js_sq():
    return f"<html><body><script>var v = '{request.args.get('q','')}';</script></body></html>"


@app.get("/js_tpl")
def js_tpl():
    return f"<html><body><script>var v = `{request.args.get('q','')}`;</script></body></html>"


@app.get("/js_code")
def js_code():
    return f"<html><body><script>var v = {request.args.get('q','')};</script></body></html>"


@app.get("/href")
def href():
    return f'<html><body><a href="{request.args.get("redir","")}">click</a></body></html>'


@app.get("/comment")
def comment():
    return f"<html><body><!-- debug: {request.args.get('q','')} --></body></html>"


@app.get("/css")
def css():
    return f"<html><head><style>.x{{ color: {request.args.get('q','')}; }}</style></head><body>x</body></html>"


@app.get("/safe")
def safe():
    return f"<html><body><p>Hello {escape(request.args.get('q',''))}</p></body></html>"


# ───────── POST sinks ─────────

@app.post("/post")
def post_form():
    return f"<html><body><p>Welcome {request.form.get('name','')}</p></body></html>"


@app.post("/json")
def post_json():
    data = request.get_json(silent=True) or {}
    return f'<html><body><script>var label = "{data.get("label","")}";</script></body></html>'


# ───────── blacklist sinks ─────────

@app.get("/bl_lt_gt")
def bl_lt_gt():
    q = request.args.get("q", "").replace("<", "").replace(">", "")
    return f"<html><body><p>Hello {q}</p></body></html>"


@app.get("/bl_quotes")
def bl_quotes():
    q = request.args.get("q", "").replace('"', "").replace("'", "")
    return f'<html><body><input value="{q}"></body></html>'


@app.get("/bl_script_kw")
def bl_script_kw():
    q = request.args.get("q", "").replace("script", "")
    return f"<html><body><p>Hello {q}</p></body></html>"


@app.get("/htmlentity_only")
def htmlentity_only():
    q = request.args.get("q", "").replace("<", "&lt;").replace(">", "&gt;")
    return f'<html><body><input value="{q}"></body></html>'


@app.get("/js_escape_dq")
def js_escape_dq():
    q = request.args.get("q", "").replace('"', '\\"')
    return f'<html><body><script>var v = "{q}";</script></body></html>'


@app.get("/href_bl_js")
def href_bl_js():
    redir = request.args.get("redir", "").replace("javascript:", "")
    return f'<html><body><a href="{redir}">click</a></body></html>'


@app.get("/strip_xss")
def strip_xss():
    q = request.args.get("q", "")
    for c in '<>"\'':
        q = q.replace(c, "")
    return f"<html><body><p>Hello {q}</p></body></html>"


@app.get("/url_encode_all")
def url_encode_all():
    q = quote(request.args.get("q", ""), safe="")
    return f"<html><body><p>Hello {q}</p></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
