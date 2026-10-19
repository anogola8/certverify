"""QR code generation for certificates."""
import io
from urllib.parse import urljoin

import qrcode


def generate_qr_png(data: str, box_size: int = 8, border: int = 2) -> bytes:
    """Return PNG bytes for a QR code that encodes `data`."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def verification_url(certificate_id: str, request=None) -> str:
    """
    Build a fully-qualified URL that the QR code will point to.
    Prefers the request's host when available.
    """
    path = f"/verify/{certificate_id}/"
    if request is not None:
        return request.build_absolute_uri(path)
    return urljoin("http://127.0.0.1:8000", path)