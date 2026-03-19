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


def _render_settings(settings: Dict[str, Any]) -> str:
    if not settings:
        return ""

    version = settings.get("tdesktop_version", "N/A")

    bool_rows = ""
    for key, label in [
        ("auto_start", "Auto start"),
        ("start_minimized", "Start minimized"),
        ("send_to_menu", "Send to menu"),
        ("auto_update", "Auto update"),
    ]:
        val = settings.get(key)
        if val is not None:
            color = "#166534" if val else "#dc2626"
            bool_rows += f"<tr><td>{label}</td><td style='color:{color}'>{val}</td></tr>"

    detail_rows = ""
    if settings.get("last_update_check") and settings["last_update_check"] > 0:
        from datetime import datetime
        try:
            dt = datetime.fromtimestamp(settings["last_update_check"])
            detail_rows += f"<tr><td>Last update check</td><td>{dt.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>"
        except (OSError, ValueError):
            detail_rows += f"<tr><td>Last update check</td><td>{settings['last_update_check']}</td></tr>"

    scale = settings.get("scale_percent")
    if scale is not None:
        detail_rows += f"<tr><td>Scale</td><td>{'auto' if scale == 0 else f'{scale}%'}</td></tr>"

    if settings.get("auto_lock") is not None:
        detail_rows += f"<tr><td>Auto lock</td><td>{settings['auto_lock']}s</td></tr>"

    if settings.get("power_saving") is not None:
        detail_rows += f"<tr><td>Power saving</td><td>{settings['power_saving']}</td></tr>"

    if settings.get("phone_number"):
        detail_rows += f"<tr><td>Phone number</td><td><b>{escape(str(settings['phone_number']))}</b></td></tr>"

    if settings.get("download_path"):
        detail_rows += f"<tr><td>Download path</td><td><code>{escape(str(settings['download_path']))}</code></td></tr>"

    if settings.get("dialog_last_path"):
        detail_rows += f"<tr><td>Last dialog path</td><td><code>{escape(str(settings['dialog_last_path']))}</code></td></tr>"

    if settings.get("lang_pack_key"):
        detail_rows += f"<tr><td>Language</td><td>{escape(str(settings['lang_pack_key']))}</td></tr>"

    send_key = settings.get("send_key")
    if send_key is not None:
        sk = {0: "Enter", 1: "Ctrl+Enter"}.get(send_key, str(send_key))
        detail_rows += f"<tr><td>Send key</td><td>{sk}</td></tr>"

    theme = settings.get("theme")
    if theme:
        mode = "night" if theme.get("night_mode") else "day"
        detail_rows += f"<tr><td>Theme mode</td><td>{mode}</td></tr>"

    bg = settings.get("background")
    if bg:
        detail_rows += f"<tr><td>Background ID</td><td>day={bg.get('day', 0)}, night={bg.get('night', 0)}</td></tr>"

    wp = settings.get("window_position")
    if wp:
        detail_rows += f"<tr><td>Window position</td><td>{wp.get('w', 0)}x{wp.get('h', 0)} at ({wp.get('x', 0)}, {wp.get('y', 0)})</td></tr>"

    conn = settings.get("connection")
    if conn:
        ctype = {0: "auto", 1: "HTTP proxy", 2: "TCP proxy", 3: "MTPROTO proxy"}.get(
            conn.get("type", 0), str(conn.get("type", 0))
        )
        detail_rows += f"<tr><td>Connection type</td><td>{ctype}</td></tr>"
        if conn.get("proxy_host"):
            detail_rows += f"<tr><td>Proxy</td><td>{escape(str(conn['proxy_host']))}:{conn.get('proxy_port', 0)}</td></tr>"

    config = settings.get("production_config")
    config_rows = ""
    if config:
        config_rows = f"""
            <tr><td>DC count</td><td>{config.get('dc_count', 'N/A')}</td></tr>
            <tr><td>DC options total</td><td>{config.get('dc_options_total', 'N/A')}</td></tr>
            <tr><td>Chat size max</td><td>{config.get('chat_size_max', 'N/A')}</td></tr>
            <tr><td>Megagroup size max</td><td>{config.get('megagroup_size_max', 'N/A')}</td></tr>
            <tr><td>Forwarded count max</td><td>{config.get('forwarded_count_max', 'N/A')}</td></tr>
            <tr><td>Edit time limit</td><td>{config.get('edit_time_limit', 'N/A')}</td></tr>
            <tr><td>Revoke time limit</td><td>{config.get('revoke_time_limit', 'N/A')}</td></tr>"""

    return f"""
    <section>
        <h2>Decrypted Settings</h2>
        <p>TDesktop version: <b>{version}</b></p>
        <table>
            {bool_rows}
            {detail_rows}
        </table>
        {f'<h3>Production Config</h3><table>{config_rows}</table>' if config_rows else ''}
    </section>"""


def _render_timeline(timeline: Dict[str, Any]) -> str:
    if not timeline:
        return ""

    anomaly_rows = ""
    for a in timeline.get("anomalies", []):
        sev = escape(a.get("severity", ""))
        sev_class = "error-msg" if sev == "CRITICAL" else ""
        anomaly_rows += (
            f"<tr>"
            f"<td class='{sev_class}'>{sev}</td>"
            f"<td>{escape(a.get('title', ''))}</td>"
            f"<td>{escape(a.get('detail', ''))}</td>"
            f"<td><code>{escape(a.get('mitre_id', ''))}</code></td>"
            f"</tr>"
        )

    activity_rows = ""
    for e in timeline.get("recent_activity", []):
        activity_rows += (
            f"<tr>"
            f"<td>{escape(str(e.get('timestamp', '')))}</td>"
            f"<td><code>{escape(e.get('path', ''))}</code></td>"
            f"</tr>"
        )

    anomalies_section = ""
    if anomaly_rows:
        anomalies_section = f"""
            <h3>Anomalies</h3>
            <table>
                <tr><th>Severity</th><th>Title</th><th>Detail</th><th>MITRE</th></tr>
                {anomaly_rows}
            </table>"""

    return f"""
    <section>
        <h2>Timeline Analysis</h2>
        <table>
            <tr><td>Files analyzed</td><td>{timeline.get('total_files', 0)}</td></tr>
            <tr><td>Earliest activity</td><td>{escape(str(timeline.get('earliest', 'N/A')))}</td></tr>
            <tr><td>Latest activity</td><td>{escape(str(timeline.get('latest', 'N/A')))}</td></tr>
            <tr><td>Anomalies detected</td><td>{len(timeline.get('anomalies', []))}</td></tr>
        </table>
        {anomalies_section}
        <h3>Recent Activity</h3>
        <table>
            <tr><th>Timestamp</th><th>Path</th></tr>
            {activity_rows}
        </table>
    </section>"""


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
    {_render_settings(data.get('settings', {}))}
    <section>
        <h2>Accounts ({len(data.get('accounts', []))})</h2>
        {accounts_html}
    </section>
    {_render_cache(data.get('cache'))}
    {_render_hashes(data.get('hashes'))}
    {_render_timeline(data.get('timeline'))}
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
