"""Content of the Teams cards and the emails. No network, no state.

Every alert is built from the same view (vuln_view): the KEV entry, plus the
SG assessment from vulnScore.py when NOTIFY_MODE=filtered.
"""
import re
from html import escape

# Orange Cyberdefense look (Orange "Boosted" palette): orange, black, white, square corners.
ORANGE, BLACK, GREY, LIGHT, LINE = "#FF7900", "#000000", "#595959", "#F6F6F6", "#CCCCCC"
RED, YELLOW, GREEN = "#CD3C14", "#FFCC00", "#228722"
FONT = "'Helvetica Neue',Helvetica,Arial,sans-serif"
BRAND = "Orange Cyberdefense"
TEAM = "CyberSOC - Vulnerability watch"

# status -> (card header, Adaptive Card color, email tag background, tag text, short label)
STATUS_STYLE = {
    None: ("\U0001F6A8 Publicly exploited vulnerability", "Attention", ORANGE, BLACK,
           "EXPLOITED"),
    "MATCH": ("\U0001F6A8 Exploited vulnerability - SG criteria met, customer and L1 notified", "Attention", RED, "#FFFFFF",
              "SG CRITERIA MET"),
    "TO_CHECK": ("⚠️ Exploited vulnerability - TO CHECK, scoring not determined, customer and L1 notified", "Warning", YELLOW, BLACK,
                 "MANUAL REVIEW"),
    "NO_MATCH": ("ℹ️ Exploited vulnerability - SG criteria not met, no email", "Default", GREY, "#FFFFFF",
                 "SG CRITERIA NOT MET"),
}

# CVSS metric -> (label, expected value, {value: meaning})
CRITERIA = (
    ("AV", "Attack vector", "N", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    ("AC", "Attack complexity", "L", {"L": "Low", "H": "High"}),
    ("PR", "Privileges required", "N", {"N": "None", "L": "Low", "H": "High"}),
    ("UI", "User interaction", "N", {"N": "None", "R": "Required", "P": "Passive", "A": "Active"}),
)
URL_RE = re.compile(r"https?://[^\s;]+")

# TO_CHECK: what the customer verifies, by assessment["check"] (set in vulnScore.py).
REVIEW_STEPS = {
    "no_vector": [
        "No CVSS score published yet (recent CVE, NVD backlog)",
        "Open CVE.org and NVD: a vector may be out now",
        "Otherwise answer the checklist from the vendor advisory",
        "Advisory too vague: check again within 24-48 h",
    ],
    "cvss_v2": [
        "Only a CVSS v2 score (old CVE): no PR / UI sub-score",
        "Look for a v3 vector on NVD",
        "Otherwise answer the checklist from the vendor advisory (v2 Au:N = PR:N)",
    ],
    "unreachable": [
        "CVE.org and/or NVD could not be reached by the script",
        "Open CVE.org and NVD, compare the vector with the checklist",
        "No vector: answer the checklist from the vendor advisory",
    ],
    "rejected": [
        "CVE REJECTED on CVE.org but still listed in the CISA KEV",
        "CVE.org: read the rejection reason, note the replacement CVE ID",
        "CISA KEV: confirm which CVE ID is listed now",
        "Run the checklist on the replacement CVE",
    ],
    "bad_vector": [
        "CVSS vector incomplete or unsupported version (see Decision)",
        "Look for a complete v3.x / v4.0 vector on NVD and CVE.org",
        "Missing sub-scores: answer from the vendor advisory",
    ],
    "type_unknown": [
        "CVSS criteria already met (see SG criteria)",
        "Type unknown: no CWE and no explicit wording",
        "Read the vendor advisory to decide the type",
    ],
    "error": [
        "Automatic assessment failed",
        "Open CVE.org and NVD, compare the vector with the checklist",
        "No vector: answer the checklist from the vendor advisory",
    ],
}
# TO_CHECK, Teams card: one line the L1 can relay to the customer (the full steps are in the email).
REVIEW_HINT = {
    "no_vector": "No CVSS score yet: check CVE.org / NVD again, or assess from the vendor advisory",
    "cvss_v2": "Only CVSS v2: look for a v3 vector on NVD, or assess from the vendor advisory",
    "unreachable": "CVE.org / NVD unreachable by the script: compare their vector with the SG criteria",
    "rejected": "CVE rejected on CVE.org: assess the replacement CVE listed in the CISA KEV",
    "bad_vector": "Incomplete CVSS vector: look for a full v3.x / v4.0 vector on NVD and CVE.org",
    "type_unknown": "CVSS criteria met, type unknown: confirm RCE or Authentication Bypass from the vendor advisory",
    "error": "Automatic assessment failed: compare the CVE.org / NVD vector with the SG criteria",
}
REVIEW_CHECKLIST = [
    "AV:N - exploitable over the network",
    "AC:L - no special condition to exploit",
    "PR:N - no account or login needed",
    "UI:N - no user action (click, file to open)",
    "Impact - High on confidentiality, integrity or availability",
    "Type - RCE (code / command execution) or Authentication Bypass (access without valid credentials)",
]
REVIEW_OUTCOME = [
    "All criteria met: SG criteria met, handle it as a priority",
    "One criterion not met (e.g. XSS, path traversal, DoS, info disclosure): no action",
]


def _cve_id(vuln):
    return vuln.get("cveID") or vuln.get("id")


def _advisories(notes):
    """Vendor advisory URLs from the KEV 'notes' field (CISA and NVD links removed)."""
    return [u for u in URL_RE.findall(notes or "")
            if "cisa.gov" not in u and "nvd.nist.gov" not in u]


def _criteria(assessment):
    """[(label, shown value, ok)] for the SG criteria, or [] if no usable vector."""
    vector = (assessment or {}).get("vector")
    if not vector:
        return []
    p = {}
    for seg in vector.split("/"):
        k, sep, v = seg.partition(":")
        if sep:
            p[k] = v
    version = p.get("CVSS", "")
    impact = ("C", "I", "A") if version.startswith("3.") else ("VC", "VI", "VA") if version == "4.0" else None
    if not impact:
        return []
    rows = []
    for key, label, expected, names in CRITERIA:
        value = p.get(key)
        rows.append((label, f"{names.get(value, value or '?')} ({key}:{value or '?'})", value == expected))
    impacts = [f"{k}:{p.get(k, '?')}" for k in impact]
    rows.append(("Impact (one High)", " / ".join(impacts), any(p.get(k) == "H" for k in impact)))
    vtype = assessment.get("type")
    if assessment.get("status") == "MATCH":
        rows.append(("Type RCE / Auth bypass", vtype, True))
    elif assessment.get("status") == "NO_MATCH" and all(ok for _, _, ok in rows):
        rows.append(("Type RCE / Auth bypass", ", ".join(assessment.get("cwes") or []) or "other", False))
    return rows


def vuln_view(vuln):
    """Everything an alert shows, as plain strings."""
    cid = _cve_id(vuln) or ""
    a = vuln.get("assessment") or {}
    cwes = a.get("cwes") or vuln.get("cwes") or []
    links = [("CVE.org", f"https://www.cve.org/CVERecord?id={cid}"),
             ("NVD", f"https://nvd.nist.gov/vuln/detail/{cid}")]
    links += [("Vendor advisory", u) for u in _advisories(vuln.get("notes"))[:2]]
    links.append(("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                              f"?search_api_fulltext={cid}"))
    facts = [
        ("Vendor / product", f"{vuln.get('vendorProject', '')} / {vuln.get('product', '')}"),
        ("Added to KEV", vuln.get("dateAdded") or "-"),
        ("CISA due date", vuln.get("dueDate") or "-"),
        ("Ransomware use", vuln.get("knownRansomwareCampaignUse") or "Unknown"),
        ("CWE", ", ".join(cwes) or "-"),
    ]
    if a:
        facts.append(("CVSS vector", a.get("vector") or "not available"))
        facts.append(("Vector source", a.get("source") or "-"))
        if a.get("type"):
            facts.append(("Type", f"{a['type']} ({a.get('type_evidence')})"))
    return {
        "cid": cid,
        "status": a.get("status"),
        "reason": a.get("reason"),
        "name": vuln.get("vulnerabilityName") or f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}",
        "description": vuln.get("shortDescription") or "",
        "facts": facts,
        "criteria": _criteria(a),
        "review": _review(a),
        "hint": REVIEW_HINT.get(a.get("check"), REVIEW_HINT["error"]) if a.get("status") == "TO_CHECK" else None,
        "links": links,
    }


def _review(assessment):
    """[(section title, [bullets])] for TO_CHECK, else []."""
    if assessment.get("status") != "TO_CHECK":
        return []
    check = assessment.get("check")
    checklist = REVIEW_CHECKLIST[-1:] if check == "type_unknown" else REVIEW_CHECKLIST
    return [("What to do", REVIEW_STEPS.get(check, REVIEW_STEPS["error"])),
            ("Checklist", checklist),
            ("Outcome", REVIEW_OUTCOME)]


# ---------- Teams ----------

def _card_section(vuln, first):
    v = vuln_view(vuln)
    items = [
        {"type": "TextBlock", "text": v["cid"], "size": "ExtraLarge", "weight": "Bolder",
         "spacing": "Medium", "separator": not first},
        {"type": "TextBlock", "text": v["name"], "weight": "Bolder", "wrap": True, "spacing": "None"},
    ]
    if v["description"]:
        items.append({"type": "TextBlock", "text": v["description"], "wrap": True, "isSubtle": True})
    items.append({"type": "FactSet", "facts": [{"title": t, "value": val} for t, val in v["facts"]]})
    if v["criteria"]:
        items.append({"type": "TextBlock", "text": "SG criteria", "weight": "Bolder", "spacing": "Medium"})
        items.append({"type": "FactSet", "facts": [
            {"title": label, "value": ("✅ " if ok else "❌ ") + value}
            for label, value, ok in v["criteria"]]})
    if v["reason"]:
        items.append({"type": "TextBlock", "text": f"**Decision:** {v['reason']}", "wrap": True,
                      "spacing": "Medium"})
    if v["hint"]:
        # The customer (SG) does the review, from the email. The L1 only relays this if asked.
        items.append({"type": "TextBlock", "wrap": True, "spacing": "Medium",
                      "text": f"**Review by the customer (steps in the email).** If asked: {v['hint']}."})
    items.append({"type": "ActionSet", "actions": [
        {"type": "Action.OpenUrl", "title": label, "url": url} for label, url in v["links"]]})
    return items


def build_card(vulns, type_cve="critical"):
    """One Adaptive Card. body[0] is the header."""
    status = (vulns[0].get("assessment") or {}).get("status") if vulns else None
    title, color = STATUS_STYLE.get(status, STATUS_STYLE[None])[:2]
    if len(vulns) > 1:
        title += f" ({len(vulns)})"
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "color": color,
             "text": title, "wrap": True}]
    for i, v in enumerate(vulns):
        body += _card_section(v, first=i == 0)
    body.append({"type": "TextBlock", "text": f"\U0001F7E7 **{BRAND}** | {TEAM}", "size": "Small",
                 "isSubtle": True, "separator": True, "spacing": "Medium"})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "msteams": {"width": "Full"},
                "body": body,
            },
        }],
    }


def summary_view(s):
    """Facts and sections of the daily summary. `s` comes from daily_summary.summarize().

    Sections: [(title, [(cve dict or None, text)])], empty sections removed.
    """
    runs = f"{s['runs']} ({s['runs_ok']} OK, {s['runs_failed']} failed)"
    if s["first"]:
        runs += f" · {s['first']} → {s['last']}"
    facts = [
        ("Script runs", runs),
        ("Mode", ", ".join(s["modes"]) or "-"),
        ("CVEs processed", str(len(s["escalated"]) + len(s["not_escalated"]) + len(s["pending"]))),
        ("Escalated to customer", str(len(s["escalated"]))),
        ("Not escalated", str(len(s["not_escalated"]))),
        ("Email failed (retry next run)", str(len(s["pending"]))),
        ("Postponed (limit)", str(s["postponed"])),
        ("Teams card failures", str(s["teams_failed"])),
    ]

    def label(c):
        status = c.get("status") or "EXPLOITED"
        return f"{status} - {c['type']}" if c.get("type") else status

    sections = [
        ("\U0001F6A8 Escalated to customer (email sent)", [(c, label(c)) for c in s["escalated"]]),
        ("ℹ️ Not escalated", [(c, c.get("reason") or "SG criteria not met") for c in s["not_escalated"]]),
        ("⚠️ Email failed, will be retried", [(c, label(c)) for c in s["pending"]]),
        ("❌ Failed runs", [(None, err) for err in s["errors"]]),
    ]
    return {
        "ok": not (s["runs_failed"] or s["pending"]),
        "facts": facts,
        "sections": [(title, lines) for title, lines in sections if lines],
        "empty": not (s["escalated"] or s["not_escalated"] or s["pending"]),
    }


def _summary_line(c, text, bold=lambda x: x, esc=lambda x: x):
    if c is None:
        return esc(text)
    return f"{bold(esc(c['cve']))} · {esc(c.get('vendor') or '')} / {esc(c.get('product') or '')} · {esc(text)}"


NO_ENTRY = "No new KEV entry processed today."


def build_summary_card(day, s):
    """Daily summary card. body[0] is the header."""
    v = summary_view(s)
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True,
             "color": "Good" if v["ok"] else "Attention",
             "text": f"\U0001F4CA Daily summary - KEV watch - {day}"},
            {"type": "FactSet", "facts": [{"title": t, "value": val} for t, val in v["facts"]]}]
    for title, lines in v["sections"]:
        body.append({"type": "TextBlock", "text": title, "weight": "Bolder", "spacing": "Medium"})
        body.append({"type": "TextBlock", "wrap": True, "spacing": "Small", "text": "\n".join(
            "- " + _summary_line(c, t, lambda x: f"**{x}**") for c, t in lines)})
    if v["empty"]:
        body.append({"type": "TextBlock", "text": NO_ENTRY, "spacing": "Medium"})
    body.append({"type": "TextBlock", "text": f"\U0001F7E7 **{BRAND}** | {TEAM}", "size": "Small",
                 "isSubtle": True, "separator": True, "spacing": "Medium"})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "msteams": {"width": "Full"},
                "body": body,
            },
        }],
    }


# ---------- Email ----------

TD = f'style="padding:8px 0;border-bottom:1px solid {LINE};vertical-align:top;font-size:14px"'
TH = f'style="padding:8px 16px 8px 0;border-bottom:1px solid {LINE};vertical-align:top;font-size:14px;color:{GREY};white-space:nowrap"'
H2 = f'style="margin:28px 0 8px;font-size:16px;font-weight:bold;color:{BLACK};border-left:4px solid {ORANGE};padding-left:8px"'


def _page(hero, content, footer):
    """Orange Cyberdefense email page: black header, `hero` (title block), `content`, black footer."""
    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#EEEEEE">
<table width="100%" cellspacing="0" cellpadding="0" style="background:#EEEEEE"><tr><td align="center" style="padding:24px 10px">
<table width="640" cellspacing="0" cellpadding="0" style="max-width:640px;width:100%;background:#FFFFFF;font-family:{FONT};color:{BLACK}">
<tr><td style="background:{BLACK};padding:18px 28px">
<table cellspacing="0" cellpadding="0" width="100%"><tr>
<td width="44" valign="bottom"><div style="width:44px;height:44px;background:{ORANGE};position:relative">
<span style="display:block;padding-top:27px;padding-left:5px;font-size:10px;font-weight:bold;color:#FFFFFF;line-height:10px">orange</span></div></td>
<td style="padding-left:14px;color:#FFFFFF;font-size:18px;font-weight:bold;line-height:22px" valign="bottom">{BRAND}<br>
<span style="font-size:12px;font-weight:normal;color:{LINE}">{TEAM}</span></td>
</tr></table></td></tr>
<tr><td style="height:4px;background:{ORANGE};font-size:0;line-height:0">&nbsp;</td></tr>
<tr><td style="padding:28px 28px 8px">
{hero}</td></tr>
<tr><td style="padding:12px 28px 28px;font-size:14px;line-height:1.5">
{content}</td></tr>
<tr><td style="background:{BLACK};padding:20px 28px;font-size:12px;line-height:1.6;color:{LINE};white-space:pre-line">{footer}</td></tr>
<tr><td style="background:{BLACK};padding:0 28px 20px;font-size:12px;color:#FFFFFF"><b style="color:{ORANGE}">{BRAND}</b> &middot; {TEAM}</td></tr>
</table></td></tr></table>
</body></html>"""


def render_mail(vuln, intro, footer):
    """(plain text, HTML) bodies for one CVE. `intro` says why the reader gets it."""
    v = vuln_view(vuln)
    tag_bg, tag_fg, label = STATUS_STYLE.get(v["status"], STATUS_STYLE[None])[2:]

    text = [f"{BRAND} | {TEAM}", "", f"[{label}] {v['cid']} - {v['name']}", "", intro, ""]
    if v["description"]:
        text += [v["description"], ""]
    text += [f"{t}: {val}" for t, val in v["facts"]]
    if v["criteria"]:
        text += ["", "SG criteria:"]
        text += [f"  [{'OK' if ok else 'KO'}] {lbl}: {val}" for lbl, val, ok in v["criteria"]]
    if v["reason"]:
        text += ["", f"Decision: {v['reason']}"]
    if v["review"]:
        text += ["", "How to review:"]
        for title, bullets in v["review"]:
            text += [f"  {title}:"] + [f"    - {b}" for b in bullets]
    text +=["", "Links:"] + [f"  {lbl}: {url}" for lbl, url in v["links"]] + ["", footer]

    e = escape
    facts = "".join(f"<tr><td {TH}>{e(t)}</td><td {TD}>{e(val)}</td></tr>" for t, val in v["facts"])
    criteria = ""
    if v["criteria"]:
        rows = "".join(
            f"<tr><td {TH}>{e(lbl)}</td><td {TD}>{e(val)}</td>"
            f'<td {TD} align="right"><b style="color:{GREEN if ok else RED};font-size:16px">'
            f'{"&#10004;" if ok else "&#10008;"}</b></td></tr>'
            for lbl, val, ok in v["criteria"])
        criteria = (f"<h2 {H2}>SG criteria</h2>"
                    f'<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">{rows}</table>')
    reason = (f'<p style="margin:20px 0 0;padding:12px 14px;background:{LIGHT};border-left:4px solid {tag_bg};font-size:14px">'
              f'<b>Decision:</b> {e(v["reason"])}</p>') if v["reason"] else ""
    review = ""
    if v["review"]:
        review = f"<h2 {H2}>How to review</h2>" + "".join(
            f'<p style="margin:12px 0 4px;font-size:14px;font-weight:bold">{e(title)}</p>'
            f'<ul style="margin:0;padding-left:20px;font-size:14px;line-height:1.5">'
            + "".join(f'<li style="margin:0 0 4px">{e(b)}</li>' for b in bullets) + "</ul>"
            for title, bullets in v["review"])
    links = "".join(
        f'<a href="{e(url)}" style="display:inline-block;margin:0 8px 8px 0;padding:9px 16px;font-size:14px;'
        f'font-weight:bold;text-decoration:none;'
        + (f'background:{ORANGE};color:{BLACK};border:2px solid {ORANGE}' if i == 0
           else f'background:#FFFFFF;color:{BLACK};border:2px solid {BLACK}')
        + f'">{e(lbl)}</a>'
        for i, (lbl, url) in enumerate(v["links"]))
    hero = f"""<span style="display:inline-block;background:{tag_bg};color:{tag_fg};font-size:12px;font-weight:bold;letter-spacing:1px;padding:5px 10px">{e(label)}</span>
<span style="display:inline-block;color:{GREY};font-size:12px;font-weight:bold;letter-spacing:1px;padding:5px 0 5px 8px">CISA KEV</span>
<div style="font-size:30px;font-weight:bold;margin-top:14px;line-height:34px">{e(v["cid"])}</div>
<div style="font-size:17px;font-weight:bold;margin-top:6px;line-height:22px">{e(v["name"])}</div>
"""
    content = f"""<p style="margin:0 0 12px">{e(intro)}</p>
<p style="margin:0 0 8px;color:{GREY}">{e(v["description"])}</p>
<h2 {H2}>Details</h2>
<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">{facts}</table>
{criteria}
{reason}
{review}
<div style="margin-top:24px">{links}</div>
"""
    html = _page(hero, content, e(footer))
    return "\n".join(text), html


def render_summary_mail(day, s):
    """(plain text, HTML) bodies of the daily summary email."""
    v = summary_view(s)
    text = [f"{BRAND} | {TEAM}", "", f"Daily summary - KEV watch - {day}", ""]
    text += [f"{t}: {val}" for t, val in v["facts"]]
    for title, lines in v["sections"]:
        text += ["", title] + ["  - " + _summary_line(c, t) for c, t in lines]
    if v["empty"]:
        text += ["", NO_ENTRY]

    e = escape
    tag_bg, tag_fg, label = (GREEN, "#FFFFFF", "ALL OK") if v["ok"] else (RED, "#FFFFFF", "ACTION NEEDED")
    hero = (f'<span style="display:inline-block;background:{tag_bg};color:{tag_fg};font-size:12px;font-weight:bold;'
            f'letter-spacing:1px;padding:5px 10px">{label}</span>'
            f'<span style="display:inline-block;color:{GREY};font-size:12px;font-weight:bold;letter-spacing:1px;'
            f'padding:5px 0 5px 8px">CISA KEV</span>\n'
            f'<div style="font-size:30px;font-weight:bold;margin-top:14px;line-height:34px">Daily summary</div>\n'
            f'<div style="font-size:17px;font-weight:bold;margin-top:6px;line-height:22px">{e(day)}</div>\n')
    facts = "".join(f"<tr><td {TH}>{e(t)}</td><td {TD}>{e(val)}</td></tr>" for t, val in v["facts"])
    content = f'<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">{facts}</table>'
    for title, lines in v["sections"]:
        content += (f"<h2 {H2}>{e(title)}</h2>"
                    f'<ul style="margin:0;padding-left:20px;font-size:14px;line-height:1.5">'
                    + "".join(f'<li style="margin:0 0 4px">{_summary_line(c, t, lambda x: f"<b>{x}</b>", e)}</li>'
                              for c, t in lines) + "</ul>")
    if v["empty"]:
        content += f'<p style="margin:20px 0 0">{NO_ENTRY}</p>'
    return "\n".join(text), _page(hero, content, "Internal daily summary, not sent to the customer.")
