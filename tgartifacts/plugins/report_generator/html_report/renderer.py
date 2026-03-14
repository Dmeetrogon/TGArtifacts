from html import escape
from pathlib import Path
from typing import Any, Dict


def _render_metadata(meta: Dict[str, Any]) -> str:
    return f"""
    <section>
        <h2>Metadata</h2>
        <table>
            <tr><td>Timestamp</td><td>{escape(str(meta.get('timestamp', '')))}</td></tr>
            <tr><td>tdata path</td><td><code>{escape(str(meta.get('tdata_path', '')))}</code></td></tr>
            <tr><td>Passcode provided</td><td>{'Yes' if meta.get('passcode_provided') else 'No'}</td></tr>
        </table>
    </section>"""


def _render_account(acc: Dict[str, Any]) -> str:
    if not acc.get("success"):
        return f"""
        <div class="account error">
            <h3>Account: {escape(str(acc.get('account_dir', '?')))}</h3>
            <p class="error-msg">Error: {escape(str(acc.get('error', 'unknown')))}</p>
        </div>"""

    key_ids_rows = ""
    for dc, kid in (acc.get("auth_key_ids") or {}).items():
        key_ids_rows += f"<tr><td>DC {escape(str(dc))}</td><td><code>{escape(kid)}</code></td></tr>"

    validation = acc.get("validation") or {}
    v_status = validation.get("status", "n/a")
    v_class = {"valid": "valid", "invalid": "invalid", "skipped": "skipped"}.get(v_status, "")
    v_detail = ""
    if v_status == "valid":
        name = f"{validation.get('first_name', '')} {validation.get('last_name', '')}".strip()
        username = validation.get("username", "")
        phone = validation.get("phone", "")
        v_detail = f"{escape(name)} @{escape(username)} ({escape(phone)})"
    elif v_status == "skipped":
        v_detail = escape(str(validation.get("reason", "")))
    elif v_status == "invalid":
        v_detail = escape(str(validation.get("error", "")))

    sessions_html = ""
    for s in acc.get("sessions") or []:
        ss = s.get("string_session", "")
        sessions_html += f"<code class='session'>{escape(ss[:60])}...</code><br>"

    return f"""
        <div class="account">
            <h3>Account: {escape(str(acc.get('account_dir', '')))}</h3>
            <table>
                <tr><td>User ID</td><td>{acc.get('user_id', 'N/A')}</td></tr>
                <tr><td>DC ID</td><td>{acc.get('dc_id', 'N/A')}</td></tr>
                <tr><td>Passcode</td><td>{'Yes' if acc.get('has_passcode') else 'No'}</td></tr>
            </table>
            <h4>Auth Key IDs</h4>
            <table>{key_ids_rows}</table>
            <h4>Session Validation <span class="badge {v_class}">{escape(v_status)}</span></h4>
            <p>{v_detail}</p>
            {f'<h4>Sessions</h4>{sessions_html}' if sessions_html else ''}
        </div>"""


def _render_cache(cache: Dict[str, Any]) -> str:
    if not cache:
        return "<section><h2>Cache Extraction</h2><p>No data</p></section>"
    return f"""
    <section>
        <h2>Cache Extraction</h2>
        <table>
            <tr><td>Total files</td><td>{cache.get('total', 0)}</td></tr>
            <tr><td>Successfully decrypted</td><td>{cache.get('success', 0)}</td></tr>
            <tr><td>Streaming reassembled</td><td>{cache.get('streaming', 0)}</td></tr>
            <tr><td>Failed</td><td>{cache.get('failed', 0)}</td></tr>
        </table>
    </section>"""


def _render_hashes(hashes: Dict[str, Any]) -> str:
    if not hashes:
        return ""
    types = hashes.get("types", {})
    rows = "".join(
        f"<tr><td>{escape(t)}</td><td>{c}</td></tr>"
        for t, c in sorted(types.items())
    )
    return f"""
    <section>
        <h2>File Hashes</h2>
        <p>Total files hashed: {hashes.get('total', 0)}</p>
        <p>Report: <code>{escape(str(hashes.get('report', '')))}</code></p>
        <table>
            <tr><th>Type</th><th>Count</th></tr>
            {rows}
        </table>
    </section>"""


STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 900px; margin: 40px auto; padding: 0 20px; color: #333; }
h1 { border-bottom: 2px solid #2563eb; padding-bottom: 8px; }
h2 { color: #1e40af; margin-top: 32px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
td, th { border: 1px solid #ddd; padding: 6px 12px; text-align: left; }
th { background: #f1f5f9; }
code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
.session { word-break: break-all; font-size: 0.85em; }
.account { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; }
.account.error { border-color: #fca5a5; background: #fef2f2; }
.error-msg { color: #dc2626; }
.badge { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
.badge.valid { background: #dcfce7; color: #166534; }
.badge.invalid { background: #fef2f2; color: #dc2626; }
.badge.skipped { background: #fef9c3; color: #854d0e; }
"""


def render_html(data: Dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    accounts_html = ""
    for acc in data.get("accounts", []):
        accounts_html += _render_account(acc)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TGArtifacts Report</title>
    <style>{STYLE}</style>
</head>
<body>
    <h1>TGArtifacts Report</h1>
    {_render_metadata(data.get('metadata', {}))}
    <section>
        <h2>Accounts ({len(data.get('accounts', []))})</h2>
        {accounts_html}
    </section>
    {_render_cache(data.get('cache'))}
    {_render_hashes(data.get('hashes'))}
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
