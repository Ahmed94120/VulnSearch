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
    "MATCH": ("\U0001F6A8 Exploited vulnerability - SG criteria met, L1 notified", "Attention", RED, "#FFFFFF",
              "SG CRITERIA MET"),
    "TO_CHECK": ("⚠️ Exploited vulnerability - TO CHECK, scoring not determined", "Warning", YELLOW, BLACK,
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

# TO_CHECK: what the analyst verifies, by assessment["check"] (set in vulnScore.py).
REVIEW_CRITERIA = ("SG criteria: AV:N, AC:L, PR:N, UI:N, at least one High impact on C/I/A, "
                   "and type RCE or Authentication Bypass.")
_ASSESS_FROM_ADVISORY = ("From the vendor advisory and the description, answer: exploitable over the network "
                         "(AV:N)? Low complexity, no special conditions (AC:L)? Without any account or "
                         "authentication (PR:N)? Without user action, e.g. no click or file to open (UI:N)? "
                         "High impact on confidentiality, integrity or availability?")
_ASSESS_TYPE = ("Type: arbitrary code or command execution = RCE; access to the product or its data without "
                "valid credentials = Authentication Bypass; anything else (XSS, path traversal, "
                "information disclosure, DoS...) = criteria not met.")
REVIEW_STEPS = {
    "no_vector": [
        "No CVSS score is published yet, which is common for a CVE added to the KEV in the last days "
        "(NVD enrichment backlog). Open the CVE.org and NVD links: a vector may have been published since.",
        _ASSESS_FROM_ADVISORY,
        _ASSESS_TYPE,
        "If the advisory is too vague to decide, check CVE.org / NVD again within 24-48 h.",
    ],
    "cvss_v2": [
        "Only a CVSS v2 score exists (old CVE): v2 has no PR or UI sub-score. Check NVD for a v3 vector "
        "added since.",
        _ASSESS_FROM_ADVISORY + " In v2, Au:N means no authentication (PR:N).",
        _ASSESS_TYPE,
    ],
    "unreachable": [
        "CVE.org and/or NVD could not be reached by the script. Open the CVE.org and NVD links.",
        "If a CVSS v3 / v4 vector is shown, compare it with the criteria above; otherwise follow the "
        "vendor advisory: " + _ASSESS_FROM_ADVISORY,
        _ASSESS_TYPE,
    ],
    "rejected": [
        "The CVE is REJECTED on CVE.org but still listed in the CISA KEV. Open the CVE.org link and read "
        "the rejection reason: it usually names the replacement CVE ID.",
        "Open the CISA KEV link to confirm which CVE ID CISA lists now.",
        "Assess the replacement CVE against the criteria (its CVSS vector on CVE.org / NVD, then its type).",
    ],
    "bad_vector": [
        "The published CVSS vector is incomplete or uses an unsupported version (see Decision). Open the "
        "NVD and CVE.org links and look for a complete v3.x / v4.0 vector.",
        "Fill in the missing sub-scores from the vendor advisory: " + _ASSESS_FROM_ADVISORY,
        _ASSESS_TYPE,
    ],
    "type_unknown": [
        "The CVSS criteria are met (see SG criteria above); only the type is missing: no CWE and no "
        "explicit wording in the description.",
        "Read the vendor advisory. " + _ASSESS_TYPE,
    ],
    "error": [
        "The automatic assessment crashed (see Decision, details in vulnscan.log). Do the full check by hand.",
        "Open the CVE.org and NVD links and compare the CVSS vector with the criteria; without a vector, "
        "use the vendor advisory: " + _ASSESS_FROM_ADVISORY,
        _ASSESS_TYPE,
    ],
}
REVIEW_DECISION = ("Conclusion: all criteria met = treat as SG criteria met and notify L1 with this email. "
                   "At least one criterion not met = no action.")


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
        "links": links,
    }


def _review(assessment):
    """Numbered manual-review steps for TO_CHECK, else []."""
    if assessment.get("status") != "TO_CHECK":
        return []
    steps = REVIEW_STEPS.get(assessment.get("check"), REVIEW_STEPS["error"][1:])
    return [REVIEW_CRITERIA] + steps + [REVIEW_DECISION]


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
    if v["review"]:
        items.append({"type": "TextBlock", "text": "How to review", "weight": "Bolder", "spacing": "Medium"})
        items += [{"type": "TextBlock", "text": f"{i}. {step}", "wrap": True, "spacing": "Small"}
                  for i, step in enumerate(v["review"], 1)]
    items.append({"type": "ActionSet", "actions": [
        {"type": "Action.OpenUrl", "title": label, "url": url} for label, url in v["links"]]})
    return items


def build_card(vulns, type_cve="critical"):
    """One Adaptive Card. body[0] is the header (teams_only.py prefixes it)."""
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


# ---------- Email ----------

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
        text += ["", "How to review:"] + [f"  {i}. {step}" for i, step in enumerate(v["review"], 1)]
    text +=["", "Links:"] + [f"  {lbl}: {url}" for lbl, url in v["links"]] + ["", footer]

    e = escape
    td = f'style="padding:8px 0;border-bottom:1px solid {LINE};vertical-align:top;font-size:14px"'
    th = f'style="padding:8px 16px 8px 0;border-bottom:1px solid {LINE};vertical-align:top;font-size:14px;color:{GREY};white-space:nowrap"'
    h2 = f'style="margin:28px 0 8px;font-size:16px;font-weight:bold;color:{BLACK};border-left:4px solid {ORANGE};padding-left:8px"'
    facts = "".join(f"<tr><td {th}>{e(t)}</td><td {td}>{e(val)}</td></tr>" for t, val in v["facts"])
    criteria = ""
    if v["criteria"]:
        rows = "".join(
            f"<tr><td {th}>{e(lbl)}</td><td {td}>{e(val)}</td>"
            f'<td {td} align="right"><b style="color:{GREEN if ok else RED};font-size:16px">'
            f'{"&#10004;" if ok else "&#10008;"}</b></td></tr>'
            for lbl, val, ok in v["criteria"])
        criteria = (f"<h2 {h2}>SG criteria</h2>"
                    f'<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">{rows}</table>')
    reason = (f'<p style="margin:20px 0 0;padding:12px 14px;background:{LIGHT};border-left:4px solid {tag_bg};font-size:14px">'
              f'<b>Decision:</b> {e(v["reason"])}</p>') if v["reason"] else ""
    review = ""
    if v["review"]:
        steps = "".join(f'<li style="margin:0 0 8px">{e(step)}</li>' for step in v["review"])
        review = (f"<h2 {h2}>How to review</h2>"
                  f'<ol style="margin:0;padding-left:22px;font-size:14px;line-height:1.5">{steps}</ol>')
    links = "".join(
        f'<a href="{e(url)}" style="display:inline-block;margin:0 8px 8px 0;padding:9px 16px;font-size:14px;'
        f'font-weight:bold;text-decoration:none;'
        + (f'background:{ORANGE};color:{BLACK};border:2px solid {ORANGE}' if i == 0
           else f'background:#FFFFFF;color:{BLACK};border:2px solid {BLACK}')
        + f'">{e(lbl)}</a>'
        for i, (lbl, url) in enumerate(v["links"]))
    html = f"""<!doctype html>
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
<span style="display:inline-block;background:{tag_bg};color:{tag_fg};font-size:12px;font-weight:bold;letter-spacing:1px;padding:5px 10px">{e(label)}</span>
<span style="display:inline-block;color:{GREY};font-size:12px;font-weight:bold;letter-spacing:1px;padding:5px 0 5px 8px">CISA KEV</span>
<div style="font-size:30px;font-weight:bold;margin-top:14px;line-height:34px">{e(v["cid"])}</div>
<div style="font-size:17px;font-weight:bold;margin-top:6px;line-height:22px">{e(v["name"])}</div>
</td></tr>
<tr><td style="padding:12px 28px 28px;font-size:14px;line-height:1.5">
<p style="margin:0 0 12px">{e(intro)}</p>
<p style="margin:0 0 8px;color:{GREY}">{e(v["description"])}</p>
<h2 {h2}>Details</h2>
<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">{facts}</table>
{criteria}
{reason}
{review}
<div style="margin-top:24px">{links}</div>
</td></tr>
<tr><td style="background:{BLACK};padding:20px 28px;font-size:12px;line-height:1.6;color:{LINE};white-space:pre-line">{e(footer)}</td></tr>
<tr><td style="background:{BLACK};padding:0 28px 20px;font-size:12px;color:#FFFFFF"><b style="color:{ORANGE}">{BRAND}</b> &middot; {TEAM}</td></tr>
</table></td></tr></table>
</body></html>"""
    return "\n".join(text), html
