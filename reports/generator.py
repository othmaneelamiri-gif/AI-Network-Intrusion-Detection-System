"""
PDF report generator using ReportLab.
Falls back to a plain-text report if ReportLab is not installed.
"""

import logging
import os
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.database import DatabaseManager

logger = logging.getLogger(__name__)

REPORT_DIR = "data/reports"


def generate_pdf(db: "DatabaseManager") -> str:
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORT_DIR, f"ids_report_{ts}.pdf")

    try:
        return _generate_with_reportlab(db, path)
    except ImportError:
        logger.warning("ReportLab not installed — generating text report")
        return _generate_text_report(db, path.replace(".pdf", ".txt"))


def _generate_with_reportlab(db, path: str) -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    # ── Title ──────────────────────────────────────────────────────────────
    title_style = ParagraphStyle("IDS_Title", parent=styles["Title"],
                                  fontSize=24, textColor=colors.HexColor("#0F172A"),
                                  spaceAfter=6)
    sub_style = ParagraphStyle("IDS_Sub", parent=styles["Normal"],
                                fontSize=10, textColor=colors.HexColor("#64748B"))

    story.append(Paragraph("IDS Security Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#6366F1")))
    story.append(Spacer(1, 0.5*cm))

    # ── Executive Summary ──────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    pkt_count = db.get_packet_count()
    alert_count = db.get_alert_count()
    summary_data = [
        ["Metric", "Value"],
        ["Total Packets Analysed", f"{pkt_count:,}"],
        ["Total Alerts Generated", f"{alert_count:,}"],
        ["Report Timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    t = Table(summary_data, colWidths=[8*cm, 8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366F1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # ── Alert Breakdown ────────────────────────────────────────────────────
    story.append(Paragraph("Alert Breakdown by Type", styles["Heading2"]))
    alert_summary = db.get_alert_summary()
    if alert_summary:
        rows = [["Attack Type", "Critical", "High", "Medium", "Low", "Total"]]
        for atype, severities in alert_summary.items():
            total = sum(severities.values())
            rows.append([
                atype,
                str(severities.get("CRITICAL", 0)),
                str(severities.get("HIGH", 0)),
                str(severities.get("MEDIUM", 0)),
                str(severities.get("LOW", 0)),
                str(total),
            ])
        t2 = Table(rows, colWidths=[5*cm, 2.2*cm, 2.2*cm, 2.2*cm, 2.2*cm, 2.2*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No alerts recorded.", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    # ── Recent Alerts ──────────────────────────────────────────────────────
    story.append(Paragraph("Recent Alerts (last 20)", styles["Heading2"]))
    recent = db.get_recent_alerts(limit=20)
    if recent:
        rows = [["Timestamp", "Type", "Severity", "Source IP", "Description"]]
        for a in recent:
            rows.append([
                a["timestamp"][:16],
                a["alert_type"],
                a["severity"],
                a["src_ip"],
                a["description"][:55],
            ])
        t3 = Table(rows, colWidths=[3.5*cm, 2.5*cm, 2*cm, 3*cm, 5*cm])
        severity_colors = {"CRITICAL": "#EF4444", "HIGH": "#F97316",
                           "MEDIUM": "#EAB308", "LOW": "#22C55E"}
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i, a in enumerate(recent, start=1):
            sev_hex = severity_colors.get(a["severity"], "#94A3B8")
            style.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor(sev_hex)))
            style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC")))
        t3.setStyle(TableStyle(style))
        story.append(t3)
    story.append(Spacer(1, 0.5*cm))

    # ── Top Source IPs ─────────────────────────────────────────────────────
    story.append(Paragraph("Top Source IPs", styles["Heading2"]))
    top_ips = db.get_top_src_ips(limit=10)
    if top_ips:
        rows = [["Rank", "IP Address", "Packet Count"]]
        for i, entry in enumerate(top_ips, 1):
            rows.append([str(i), entry["ip"], f"{entry['count']:,}"])
        t4 = Table(rows, colWidths=[2*cm, 8*cm, 6*cm])
        t4.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366F1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t4)

    doc.build(story)
    logger.info(f"PDF report: {path}")
    return path


def _generate_text_report(db, path: str) -> str:
    lines = [
        "=" * 60,
        "  IDS SECURITY REPORT",
        f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "=" * 60,
        "",
        f"Total Packets : {db.get_packet_count():,}",
        f"Total Alerts  : {db.get_alert_count():,}",
        "",
        "--- Alert Breakdown ---",
    ]
    for atype, severities in db.get_alert_summary().items():
        lines.append(f"  {atype}: {severities}")
    lines += ["", "--- Recent Alerts ---"]
    for a in db.get_recent_alerts(limit=20):
        lines.append(f"  [{a['severity']}] {a['timestamp'][:16]}  {a['alert_type']}  {a['src_ip']}  {a['description']}")
    lines += ["", "--- Top Source IPs ---"]
    for e in db.get_top_src_ips():
        lines.append(f"  {e['ip']}: {e['count']:,} packets")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    return path
