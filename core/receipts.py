"""PDF receipt generation. Portable, self-verifying proof of forensic analysis."""
import hashlib
import io

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image as RLImage,
)

from .qr_utils import generate_qr_png


def fingerprint_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _qr_image(url: str, size_mm: float = 40) -> RLImage:
    png = generate_qr_png(url, box_size=10, border=2)
    return RLImage(io.BytesIO(png), width=size_mm * mm, height=size_mm * mm)


def build_receipt_pdf(receipt, receipt_url: str, cert_label: str = "") -> bytes:
    """Return PDF bytes for the given VerificationReceipt."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"CertVerify receipt {receipt.id}",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, spaceAfter=6, textColor=HexColor("#312e81"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=10, leading=14)
    mono = ParagraphStyle("mono", parent=styles["Code"], fontSize=8, leading=11, textColor=HexColor("#475569"))

    story = []
    story.append(Paragraph("CertVerify", h1))
    story.append(Paragraph("Verification receipt", h2))
    story.append(Spacer(1, 4 * mm))

    verdict_color = {
        "authentic": "#15803d",
        "tampered": "#b91c1c",
        "inconclusive": "#b45309",
        "revoked": "#b91c1c",
    }.get(receipt.verdict, "#334155")

    summary = [
        ["Receipt ID", str(receipt.id)],
        ["Verdict", Paragraph(f'<font color="{verdict_color}"><b>{receipt.verdict.upper()}</b></font>', body)],
        ["Confidence", f"{receipt.confidence:.2f}"],
        ["Issued at", receipt.issued_at.strftime("%Y-%m-%d %H:%M:%S")],
        ["Document SHA-256", Paragraph(receipt.document_fingerprint, mono)],
    ]
    if cert_label:
        summary.append(["Certificate", Paragraph(cert_label, body)])

    tbl = Table(summary, colWidths=[45 * mm, 105 * mm])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#f8fafc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 6 * mm))

    try:
        fr = receipt.verification.forensic_report
        story.append(Paragraph("Forensic analysis", h2))
        fs = [
            ["ELA score", f"{fr.ela_score:.3f}"],
            ["Copy-move score", f"{fr.copy_move_score:.3f}"],
            ["Metadata OK", "Yes" if fr.metadata_ok else "No"],
        ]
        ftbl = Table(fs, colWidths=[45 * mm, 105 * mm])
        ftbl.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), HexColor("#f8fafc")),
        ]))
        story.append(ftbl)
        story.append(Spacer(1, 6 * mm))
    except Exception:
        pass

    story.append(Paragraph("Signature", h2))
    story.append(Paragraph(
        "This receipt is signed by the CertVerify server with Ed25519. "
        "Re-verify by scanning the QR code or checking the signature against "
        "the public key below.",
        body,
    ))
    story.append(Spacer(1, 3 * mm))

    sig_table = Table(
        [[
            _qr_image(receipt_url, 40),
            Paragraph(
                f'<b>Receipt URL</b><br/>{receipt_url}<br/><br/>'
                f'<b>Server public key</b><br/><font size="7">{receipt.signed_by_key}</font><br/><br/>'
                f'<b>Signature (base64)</b><br/><font size="7">{receipt.signature}</font>',
                mono,
            ),
        ]],
        colWidths=[45 * mm, 105 * mm],
    )
    sig_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
    ]))
    story.append(sig_table)

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "This receipt attests that the uploaded file was analyzed by CertVerify "
        "at the timestamp above. It does not prove the original certificate's "
        "authenticity - use the hash-chain lookup for that.",
        ParagraphStyle("disc", parent=body, fontSize=8, textColor=HexColor("#64748b")),
    ))

    doc.build(story)
    return buf.getvalue()
