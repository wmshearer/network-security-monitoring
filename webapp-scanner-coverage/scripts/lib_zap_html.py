"""Shared helper to pull the alert list out of a ZAP traditional-html report.

Used instead of the traditional-json report because ZAP 2.17.0's JSON
template throws a TemplateProcessingException on this install
(helper.isSystemic(alert)) and produces a truncated file. The HTML report
renders successfully and carries the same alert data in its "Alerts"
summary table (name, risk, whether it is a "systemic" finding).
"""
import re
from pathlib import Path


def extract_alerts(html_path: Path) -> list[dict]:
    html = html_path.read_text()
    if ">Alerts<" not in html or "Alert Detail" not in html:
        return []
    section = html.split(">Alerts<", 1)[1].split("Alert Detail", 1)[0]
    rows = re.findall(r"<tr>(.*?)</tr>", section, re.S)
    alerts = []
    for row in rows:
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        cells = [re.sub(r"<[^>]+>", "", c).strip() for c in cells]
        if len(cells) >= 2:
            alerts.append({"name": cells[0], "risk": cells[1]})
    return alerts
