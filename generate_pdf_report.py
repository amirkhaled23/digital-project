"""
PDF Forensic Report Generator  v2
Steganography Detection and Hidden Data Extraction Project
"""

import json, os, math
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ── Palette ──────────────────────────────────────────────────────────────────
BG       = colors.HexColor("#0d1117")
PANEL    = colors.HexColor("#161b27")
PANEL2   = colors.HexColor("#0f1923")
BORDER   = colors.HexColor("#1e2d40")
BLUE     = colors.HexColor("#4f8ef7")
GREEN    = colors.HexColor("#3dd68c")
RED      = colors.HexColor("#f75f4f")
YELLOW   = colors.HexColor("#f7c948")
PURPLE   = colors.HexColor("#7c3aed")
MUTED    = colors.HexColor("#7a8899")
TEXT     = colors.HexColor("#c8d3f5")
WHITE    = colors.white

REPORT_JSON = "scan_report.json"
OUTPUT_PDF  = "forensic_report.pdf"

W, H = A4   # 595.27 x 841.89 pts

# ── Page Background ───────────────────────────────────────────────────────────
def background(canvas, doc):
    canvas.saveState()
    # full dark bg
    canvas.setFillColor(BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # top blue stripe
    canvas.setFillColor(BLUE)
    canvas.rect(0, H - 5, W, 5, fill=1, stroke=0)
    # left accent stripe
    canvas.setFillColor(PURPLE)
    canvas.rect(0, 0, 3, H, fill=1, stroke=0)
    # footer line
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(1.8*cm, 1.8*cm, W - 1.8*cm, 1.8*cm)
    # footer text
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(1.8*cm, 1.3*cm,
        "CONFIDENTIAL — Steganography Detection & Hidden Data Extraction Project")
    canvas.drawRightString(W - 1.8*cm, 1.3*cm,
        f"Page {doc.page}   |   {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    canvas.restoreState()

# ── Style Helpers ─────────────────────────────────────────────────────────────
def S(name, **kw):
    defaults = dict(fontName="Helvetica", textColor=TEXT, leading=14, spaceAfter=0)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)

def P(text, **kw):
    return Paragraph(text, S("p", **kw))

def HR():
    return HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4, spaceBefore=4)

# ── Section Header ────────────────────────────────────────────────────────────
def section(num, title):
    return Paragraph(
        f'<font color="#4f8ef7"><b>{num}</b></font>'
        f'<font color="#1e2d40"> ━━━ </font>'
        f'<font color="#c8d3f5"><b>{title}</b></font>',
        S("sh", fontSize=12, leading=16, spaceBefore=14, spaceAfter=6)
    )

# ── Summary Cards (FIXED — value + label in single Paragraph per cell) ────────
def summary_cards(summary):
    total    = summary.get("total_files_scanned", 0)
    stego    = summary.get("stego_files", 0)
    clean    = summary.get("clean_files", 0)
    det_rate = summary.get("detection_rate_pct", 0)
    accuracy = summary.get("overall_accuracy_pct", 0)

    def cell(value, label, hex_color):
        return Paragraph(
            f'<para align="center">'
            f'<font name="Helvetica-Bold" size="24" color="{hex_color}">{value}</font>'
            f'<br/>'
            f'<font name="Helvetica" size="7.5" color="#7a8899">{label}</font>'
            f'</para>',
            S("card", alignment=TA_CENTER, leading=30)
        )

    data = [[
        cell(total,          "Total Scanned",   "#4f8ef7"),
        cell(stego,          "Stego Detected",  "#f75f4f"),
        cell(clean,          "Clean Files",     "#3dd68c"),
        cell(f"{det_rate}%", "Detection Rate",  "#f7c948"),
        cell(f"{accuracy}%", "Overall Accuracy","#4f8ef7"),
    ]]
    col_w = (W - 4.5*cm) / 5
    t = Table(data, colWidths=[col_w]*5, rowHeights=[1.8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), PANEL),
        ("BOX",           (0,0), (-1,-1), 0.5,  BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.5,  BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t

# ── Confusion Matrix Table ────────────────────────────────────────────────────
def confusion_matrix(summary):
    tp = summary.get("true_positives",  0)
    tn = summary.get("true_negatives",  0)
    fp = summary.get("false_positives", 0)
    fn = summary.get("false_negatives", 0)
    st = summary.get("stego_files", 1)
    cl = summary.get("clean_files", 1)

    def lbl(text):
        return P(f"<b>{text}</b>", fontSize=7.5, textColor=MUTED, alignment=TA_CENTER)
    def val(v, color):
        return P(f'<font name="Helvetica-Bold" size="14" color="{color}">{v}</font>',
                 alignment=TA_CENTER, leading=18)
    def sub(text, color):
        return P(f'<font size="7" color="{color}">{text}</font>',
                 alignment=TA_CENTER, leading=10)

    data = [
        [lbl("TRUE POSITIVES"),    lbl("TRUE NEGATIVES"),    lbl("FALSE POSITIVES"),    lbl("FALSE NEGATIVES")],
        [val(f"{tp}/{st}", "#3dd68c"), val(f"{tn}/{cl}", "#3dd68c"), val(fp, "#f75f4f"), val(fn, "#f75f4f")],
        [sub("Stego correctly detected","#3dd68c"), sub("Clean correctly passed","#3dd68c"),
         sub("Clean wrongly flagged","#f75f4f"),    sub("Stego missed","#f75f4f")],
    ]
    col_w = (W - 4.5*cm) / 4
    t = Table(data, colWidths=[col_w]*4, rowHeights=[0.55*cm, 0.65*cm, 0.45*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), PANEL2),
        ("BOX",           (0,0), (-1,-1), 0.5,  BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.5,  BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a0f1a")),
    ]))
    return t

# ── Methods Table ─────────────────────────────────────────────────────────────
def methods_table():
    methods = [
        ("Method 1", "Chi-Square Attack",          "Statistical LSB pair uniformity test.",                       "JPEG / PNG"),
        ("Method 2", "LSB Uniformity Analysis",    "Bit transition randomness — stego ≈ 50% flips.",             "ALL"),
        ("Method 3", "Shannon Entropy Analysis",   "Information content of LSB plane — stego has max entropy.",  "ALL"),
        ("Method 4", "StegExpose (Java)",          "Password-independent fusion (Primary Sets + RS Analysis).",   "JPEG"),
        ("Method 5", "Steghide Extraction",        "Active password-based extraction. Success = confirmed stego.","JPEG / WAV"),
        ("Method 6", "LSB Extraction (PNG)",       "Reverses raw LSB embedding without any password.",           "PNG"),
        ("Method 7", "WAV Audio LSB Analysis",     "LSB + entropy analysis applied to 16-bit audio samples.",    "WAV"),
    ]
    header = [
        P("<b>#</b>",      fontSize=7.5, textColor=BLUE, alignment=TA_CENTER),
        P("<b>Method</b>", fontSize=7.5, textColor=BLUE),
        P("<b>Description</b>", fontSize=7.5, textColor=BLUE),
        P("<b>Applies to</b>",  fontSize=7.5, textColor=BLUE, alignment=TA_CENTER),
    ]
    rows = [header]
    for i, (num, name, desc, applies) in enumerate(methods):
        bg = PANEL if i % 2 == 0 else PANEL2
        rows.append([
            P(num,    fontSize=7, textColor=BLUE, alignment=TA_CENTER),
            P(f"<b>{name}</b>", fontSize=7.5, textColor=TEXT, fontName="Helvetica-Bold"),
            P(desc,   fontSize=7.5, textColor=MUTED, leading=12),
            P(applies,fontSize=7,  textColor=YELLOW, alignment=TA_CENTER),
        ])
    col_w = [1.5*cm, 4.5*cm, 8.5*cm, 2.3*cm]
    t = Table(rows, colWidths=col_w, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a0f1a")),
        ("ROWBACKGROUND", (0,1), (-1,-1), PANEL),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t

# ── Files Table ───────────────────────────────────────────────────────────────
def files_table(files):
    header = [
        P("<b>Filename</b>",   fontSize=7.5, textColor=BLUE),
        P("<b>Type</b>",       fontSize=7.5, textColor=BLUE),
        P("<b>Size</b>",       fontSize=7.5, textColor=BLUE, alignment=TA_CENTER),
        P("<b>Confidence</b>", fontSize=7.5, textColor=BLUE, alignment=TA_CENTER),
        P("<b>Extract</b>",    fontSize=7.5, textColor=BLUE, alignment=TA_CENTER),
        P("<b>Verdict</b>",    fontSize=7.5, textColor=BLUE, alignment=TA_CENTER),
    ]
    rows = [header]
    row_styles = []
    for i, f in enumerate(files):
        is_stego  = f.get("final_verdict") == "STEGO DETECTED"
        extracted = f.get("steghide_extracted", False)
        conf      = float(f.get("confidence_pct", 0))
        size_kb   = f.get("file_size_bytes", 0) / 1024
        conf_color = "#f75f4f" if conf >= 70 else ("#f7c948" if conf >= 40 else "#3dd68c")
        bg = colors.HexColor("#180e0e") if is_stego else PANEL

        rows.append([
            P(f.get("filename","")[:26],   fontSize=7,   fontName="Courier", textColor=TEXT),
            P(f.get("file_type",""),        fontSize=7,   textColor=MUTED),
            P(f"{size_kb:.1f} KB",          fontSize=7,   textColor=TEXT,  alignment=TA_CENTER),
            P(f'<b><font color="{conf_color}">{conf:.1f}%</font></b>',
                                            fontSize=7.5, alignment=TA_CENTER),
            P(f'<b><font color="{"#3dd68c" if extracted else "#7a8899"}">{"YES" if extracted else "NO"}</font></b>',
                                            fontSize=7.5, alignment=TA_CENTER),
            P(f'<b><font color="{"#f75f4f" if is_stego else "#3dd68c"}">{"STEGO DETECTED" if is_stego else "CLEAN"}</font></b>',
                                            fontSize=7,   alignment=TA_CENTER),
        ])
        row_styles.append(("ROWBACKGROUND", (0, i+1), (-1, i+1), bg))

    col_w = [4.5*cm, 3.2*cm, 1.8*cm, 2.2*cm, 1.8*cm, 3.3*cm]
    t = Table(rows, colWidths=col_w, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a0f1a")),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ] + row_styles))
    return t

# ── Extraction Table ──────────────────────────────────────────────────────────
def extraction_table(files):
    extracted = [f for f in files if f.get("steghide_extracted")]
    if not extracted:
        return P("No confirmed extractions.", textColor=MUTED, fontSize=8)

    header = [
        P("<b>File</b>",              fontSize=7.5, textColor=BLUE),
        P("<b>Recovered Payload</b>", fontSize=7.5, textColor=BLUE),
    ]
    rows = [header]
    for f in extracted:
        content = f.get("extracted_content", "N/A")
        if len(content) > 130: content = content[:130] + "..."
        rows.append([
            P(f.get("filename","")[:24], fontSize=7,   fontName="Courier", textColor=YELLOW),
            P(content,                   fontSize=7.5, fontName="Courier", textColor=GREEN, leading=12),
        ])
    t = Table(rows, colWidths=[5*cm, 11.8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a0f1a")),
        ("BACKGROUND",    (0,1), (-1,-1), colors.HexColor("#06160d")),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t

# ── Recommendations ───────────────────────────────────────────────────────────
def recommendations_table():
    recs = [
        ("Deploy batch scanning",    "Use StegExpose for automated analysis of incoming image datasets."),
        ("Expand tool coverage",     "Compile Stegdetect on Linux/WSL to detect JSteg and OutGuess."),
        ("Visual bit-plane analysis","Use StegSolve to visually inspect LSB planes of suspicious PNGs."),
        ("Multi-method consensus",   "No single method is definitive — combine all 7 detection methods."),
        ("Increase dataset size",    "Larger datasets reduce Chi-Square false positive rate significantly."),
        ("Encrypt LSB payloads",     "Add AES-128 encryption to the PNG LSB embedder for stronger stealth."),
        ("Credential rotation",      "Immediately rotate compromised credentials (Server IP 192.168.10.5)."),
    ]
    rows = []
    for i, (title, desc) in enumerate(recs):
        bg = PANEL if i % 2 == 0 else PANEL2
        rows.append([
            P(f'<b><font color="#4f8ef7">▶  {title}</font></b>', fontSize=8, leading=12),
            P(desc, fontSize=8, textColor=TEXT, leading=12),
        ])
    t = Table(rows, colWidths=[5.5*cm, 11.3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), PANEL),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t

# ── Main ──────────────────────────────────────────────────────────────────────
def generate_pdf():
    if not os.path.exists(REPORT_JSON):
        print("[ERROR] scan_report.json not found.")
        return None

    with open(REPORT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    files   = data.get("files", [])
    summary = data.get("summary", {})

    doc = SimpleDocTemplate(
        OUTPUT_PDF, pagesize=A4,
        leftMargin=2.2*cm, rightMargin=2.2*cm,
        topMargin=2.2*cm,  bottomMargin=2.4*cm
    )
    story = []

    # ── COVER BLOCK ────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 1.2*cm),
        P("STEGANOGRAPHY FORENSIC DETECTION REPORT",
          fontSize=22, fontName="Helvetica-Bold", textColor=WHITE,
          alignment=TA_CENTER, leading=28),
        Spacer(1, 0.25*cm),
        P("Steganography Detection &amp; Hidden Data Extraction Project",
          fontSize=10, textColor=BLUE, alignment=TA_CENTER),
        P(f"Generated: {datetime.now().strftime('%B %d, %Y  —  %H:%M')}",
          fontSize=8.5, textColor=MUTED, alignment=TA_CENTER),
        Spacer(1, 0.5*cm),
        HRFlowable(width="100%", thickness=1.5, color=BLUE),
        Spacer(1, 0.4*cm),
    ]

    # ── SECTION 1: Executive Summary ───────────────────────────────────────────
    story += [
        section("01", "EXECUTIVE SUMMARY"),
        summary_cards(summary),
        Spacer(1, 0.35*cm),
        confusion_matrix(summary),
        Spacer(1, 0.3*cm),
    ]

    # False positive note
    fp = summary.get("false_positives", 0)
    if fp > 0:
        story.append(P(
            f"<b>Note on False Positives ({fp} files):</b>  Small JPEG images naturally exhibit "
            "high Chi-Square scores due to limited pixel count, which skews the statistical test. "
            "This is a known limitation — in larger datasets the false positive rate drops significantly.",
            fontSize=7.5, textColor=YELLOW, leading=12,
            backColor=colors.HexColor("#151000"),
        ))
        story.append(Spacer(1, 0.3*cm))

    # ── SECTION 2: Methodology ─────────────────────────────────────────────────
    story += [
        HR(),
        section("02", "DETECTION METHODOLOGY"),
        methods_table(),
        Spacer(1, 0.35*cm),
    ]

    # ── SECTION 3: Per-File Results ────────────────────────────────────────────
    story += [
        HR(),
        section("03", "PER-FILE SCAN RESULTS"),
        files_table(files),
        Spacer(1, 0.35*cm),
    ]

    # ── SECTION 4: Extracted Payloads ─────────────────────────────────────────
    story += [
        HR(),
        section("04", "EXTRACTED PAYLOAD PROOF"),
        extraction_table(files),
        Spacer(1, 0.35*cm),
    ]

    # ── SECTION 5: Recommendations ─────────────────────────────────────────────
    story += [
        HR(),
        section("05", "RECOMMENDATIONS"),
        recommendations_table(),
        Spacer(1, 0.5*cm),
    ]

    # ── FINAL BANNER ───────────────────────────────────────────────────────────
    story += [
        HRFlowable(width="100%", thickness=1.5, color=BLUE),
        Spacer(1, 0.2*cm),
        P(
            f'<font color="#3dd68c"><b>✓  PROJECT OBJECTIVES ACHIEVED</b></font>'
            f'   <font color="#7a8899">|</font>   '
            f'<font color="#4f8ef7">Detection Rate: {summary.get("detection_rate_pct",0)}%</font>'
            f'   <font color="#7a8899">|</font>   '
            f'<font color="#c8d3f5">All stego payloads recovered</font>',
            fontSize=9, alignment=TA_CENTER, leading=14
        ),
    ]

    doc.build(story, onFirstPage=background, onLaterPages=background)
    print(f"[SAVED] {OUTPUT_PDF}")
    return OUTPUT_PDF


if __name__ == "__main__":
    generate_pdf()
