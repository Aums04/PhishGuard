"""Generates a downloadable PDF report for a single assessment."""
import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)


def build_report_pdf(domain: str, rule_result: dict, ml_result: dict, final_verdict: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18)
    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story = [
        Paragraph("PhishGuard — Security Assessment Report", title_style),
        Spacer(1, 4 * mm),
        Paragraph(f"Target domain: <b>{domain}</b>", body),
        Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')} UTC", body),
        Paragraph(f"Overall Verdict: <b>{final_verdict}</b>", body),
        Spacer(1, 6 * mm),

        Paragraph("1. Rule-Based Findings", h2),
        Paragraph(f"Rule-engine score: {rule_result['score']}/100 — {rule_result['verdict']}", body),
    ]

    if rule_result["findings"]:
        data = [["Rule", "Severity", "Evidence"]]
        for f in rule_result["findings"]:
            data.append([f["rule"], f["severity"], f["evidence"]])
        table = Table(data, colWidths=[35 * mm, 20 * mm, 95 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No rule-based indicators were triggered.", body))

    story += [
        Spacer(1, 6 * mm),
        Paragraph("2. Machine Learning Assessment", h2),
        Paragraph(f"Predicted label: <b>{ml_result['label']}</b>", body),
        Paragraph(f"Phishing probability: {ml_result['phishing_probability']*100:.1f}%", body),
    ]
    if ml_result["top_contributions"]:
        story.append(Paragraph("Top contributing features for this prediction:", body))
        data = [["Feature", "Value", "Model Importance"]]
        for c in ml_result["top_contributions"]:
            data.append([c["feature"], str(c["value"]), f"{c['importance']:.3f}"])
        table2 = Table(data, colWidths=[60 * mm, 45 * mm, 45 * mm])
        table2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(table2)

    story += [
        Spacer(1, 6 * mm),
        Paragraph("3. Limitations & Recommendations", h2),
        Paragraph(
            "This assessment is based on static, lexical/structural analysis of the URL "
            "string only — the destination page was not visited or rendered. The model is "
            "trained on a curated academic dataset, not a live threat-intelligence feed, so "
            "results should be treated as decision support, not a definitive verdict. "
            "Lexically clean but compromised legitimate domains are out of scope.", body
        ),
        Paragraph(
            "Recommendation: do not enter credentials on this URL unless its legitimacy is "
            "independently verified. Report suspicious URLs to your organization's security team.",
            body
        ),
    ]

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
