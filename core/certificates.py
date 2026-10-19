"""PDF Certificate generation for issued credentials."""
import io
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from .qr_utils import generate_qr_png

def build_certificate_pdf(cert, verify_url: str) -> bytes:
    """Generate a landscape A4 PDF certificate."""
    buf = io.BytesIO()
    
    # Landscape A4
    width, height = landscape(A4)
    c = canvas.Canvas(buf, pagesize=(width, height))
    
    # 1. Background (Dark Navy with a Gold/Emerald Border)
    c.setFillColor(HexColor("#0f172a")) # Slate 900
    c.rect(0, 0, width, height, fill=1, stroke=0)
    
    c.setStrokeColor(HexColor("#10b981")) # Emerald
    c.setLineWidth(4)
    c.rect(15*mm, 15*mm, width - 30*mm, height - 30*mm, fill=0, stroke=1)
    
    c.setStrokeColor(HexColor("#334155"))
    c.setLineWidth(1)
    c.rect(18*mm, 18*mm, width - 36*mm, height - 36*mm, fill=0, stroke=1)

    # 2. Header
    c.setFillColor(HexColor("#10b981"))
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width/2, height - 40*mm, cert.institution.name.upper())
    
    c.setFillColor(HexColor("#94a3b8"))
    c.setFont("Helvetica", 10)
    c.drawCentredString(width/2, height - 46*mm, "OFFICIAL ACADEMIC CREDENTIAL")

    # 3. Main Body
    c.setFillColor(HexColor("#f8fafc"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(width/2, height - 75*mm, "This is to certify that")

    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 32)
    c.drawCentredString(width/2, height - 95*mm, cert.holder_name)

    c.setFillColor(HexColor("#f8fafc"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(width/2, height - 115*mm, "has been awarded the degree of")

    c.setFillColor(HexColor("#10b981"))
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width/2, height - 130*mm, cert.award)

    c.setFillColor(HexColor("#94a3b8"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(width/2, height - 145*mm, f"Programme: {cert.programme} | Classification: {cert.classification or 'Pass'}")

    # 4. Footer
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40*mm, 40*mm, "DATE OF ISSUE")
    c.setFont("Helvetica", 12)
    c.drawString(40*mm, 35*mm, cert.issued_at.strftime("%d %B %Y"))

    # 5. QR Code
    qr_png = generate_qr_png(verify_url, box_size=6, border=1)
    qr_image = ImageReader(io.BytesIO(qr_png))
    qr_size = 35 * mm
    c.drawImage(qr_image, width - 75*mm, 30*mm, width=qr_size, height=qr_size)
    
    c.setFillColor(HexColor("#94a3b8"))
    c.setFont("Helvetica", 8)
    c.drawString(width - 75*mm, 25*mm, "Scan to Verify")
    c.drawString(width - 75*mm, 21*mm, cert.certificate_id)

    # 6. Cryptographic Proof
    c.setFillColor(HexColor("#334155"))
    c.setFont("Courier", 7)
    c.drawCentredString(width/2, 25*mm, f"SIGNATURE: {cert.signature[:40]}...")
    c.drawCentredString(width/2, 21*mm, f"HASH: {cert.hash[:40]}...")

    c.showPage()
    c.save()
    return buf.getvalue()
