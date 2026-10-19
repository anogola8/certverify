"""CertVerify views."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .models import (
    Institution, Certificate, VerificationRequest,
    ForensicReport, AuditLog, VerificationReceipt,
)
from .certificates import build_certificate_pdf
from .qr_utils import generate_qr_png, verification_url
from .receipts import build_receipt_pdf, fingerprint_bytes
from .server_keys import get_private_key, get_public_key
from .signing import sign_hash
from . import forensics


def home(request):
    return render(request, "home.html", {
        "cert_count": Certificate.objects.count(),
        "institution_count": Institution.objects.filter(is_active=True).count(),
    })


def verify_view(request, certificate_id):
    cert = Certificate.objects.filter(certificate_id=certificate_id).first()
    ip = _client_ip(request)

    if cert is None:
        VerificationRequest.objects.create(
            mode="hash", queried_id=certificate_id,
            result="not_found", confidence=0.0,
            verifier_ip=ip, notes="No certificate with that ID.",
        )
        return render(request, "verify_result.html", {
            "found": False, "queried_id": certificate_id,
        })

    chain_ok = cert.verify_chain()
    sig_ok = cert.verify_signature()
    revoked = cert.revoked

    if revoked:
        result, confidence, note = "revoked", 0.0, "Certificate has been revoked."
    elif chain_ok and sig_ok:
        result, confidence, note = "authentic", 1.0, "Chain intact and signature valid."
    else:
        result, confidence = "tampered", 0.0
        note = f"chain_ok={chain_ok} sig_ok={sig_ok}"

    VerificationRequest.objects.create(
        mode="hash", certificate=cert, queried_id=certificate_id,
        result=result, confidence=confidence, verifier_ip=ip, notes=note,
    )
    AuditLog.objects.create(
        action="verify_hash", target=cert.certificate_id,
        ip_address=ip, user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
    )

    return render(request, "verify_result.html", {
        "found": True, "cert": cert,
        "chain_ok": chain_ok, "sig_ok": sig_ok, "revoked": revoked,
        "queried_id": certificate_id,
    })


@require_http_methods(["GET", "POST"])
def verify_upload(request):
    if request.method == "GET":
        return render(request, "verify_upload.html")

    upload = request.FILES.get("image")
    if not upload:
        messages.error(request, "Please choose an image file.")
        return redirect("core:verify_upload")

    upload.seek(0)
    doc_bytes = upload.read()
    fp = fingerprint_bytes(doc_bytes)
    upload.seek(0)

    tmp_path = _save_temp(upload)
    try:
        result = forensics.analyze(tmp_path)
    finally:
        import os
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    vr = VerificationRequest.objects.create(
        mode="forensic", uploaded_file=upload,
        result=result["verdict"], confidence=result["overall_confidence"],
        verifier_ip=_client_ip(request), notes=result["notes"],
    )

    report = ForensicReport.objects.create(
        verification=vr,
        ela_score=result["ela_score"],
        copy_move_score=result["copy_move_score"],
        metadata_ok=result["metadata_ok"],
        metadata_notes=result["raw"]["metadata"].get("tags", {}).get("Software", ""),
        overall_confidence=result["overall_confidence"],
        raw_json=result["raw"],
    )

    if result.get("ela_image_bytes"):
        report.ela_image.save(f"{vr.id}_ela.png", ContentFile(result["ela_image_bytes"]), save=True)
    if result.get("overlay_bytes"):
        report.overlay_image.save(f"{vr.id}_overlay.png", ContentFile(result["overlay_bytes"]), save=True)

    receipt = VerificationReceipt(
        verification=vr, document_fingerprint=fp,
        verdict=result["verdict"], confidence=result["overall_confidence"],
        signed_by_key=get_public_key(),
    )
    receipt.signature = sign_hash(get_private_key(), receipt._signing_payload())
    receipt.save()

    receipt_url = request.build_absolute_uri(reverse("core:receipt", args=[receipt.id]))
    pdf_bytes = build_receipt_pdf(receipt, receipt_url, vr.queried_id or "")
    receipt.pdf_file.save(f"{receipt.id}.pdf", ContentFile(pdf_bytes), save=True)

    AuditLog.objects.create(
        action="verify_forensic", target=str(vr.id),
        ip_address=_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
    )

    return render(request, "forensic_result.html", {
        "verification": vr, "report": report, "result": result,
        "receipt": receipt, "receipt_url": receipt_url,
    })


@login_required
def issue_certificate(request):
    institutions = Institution.objects.filter(is_active=True).order_by("code")
    if request.method == "GET":
        return render(request, "issue.html", {"institutions": institutions})

    data = request.POST
    institution = get_object_or_404(Institution, id=data.get("institution"))

    cert = Certificate(
        institution=institution,
        holder_name=data.get("holder_name", "").strip(),
        holder_id=data.get("holder_id", "").strip(),
        programme=data.get("programme", "").strip(),
        award=data.get("award", "").strip(),
        classification=data.get("classification", "").strip(),
        year_of_award=int(data.get("year_of_award") or timezone.now().year),
    )
    cert.save()

    verify_url = verification_url(cert.certificate_id, request)
    qr_bytes = generate_qr_png(verify_url)
    cert.qr_code.save(f"{cert.certificate_id}.png", ContentFile(qr_bytes), save=True)

    # Generate PDF Certificate
    pdf_bytes = build_certificate_pdf(cert, verify_url)
    cert.pdf_certificate.save(f"{cert.certificate_id}.pdf", ContentFile(pdf_bytes), save=True)

    if request.FILES.get("document"):
        cert.document = request.FILES["document"]
        cert.save(update_fields=["document"])

    AuditLog.objects.create(
        action="issue_certificate", actor=request.user,
        target=cert.certificate_id, ip_address=_client_ip(request),
    )
    messages.success(request, f"Issued {cert.certificate_id}")
    return redirect("core:certificate_detail", certificate_id=cert.certificate_id)


@login_required
def certificate_detail(request, certificate_id):
    cert = get_object_or_404(Certificate, certificate_id=certificate_id)
    return render(request, "certificate_detail.html", {
        "cert": cert, "verify_url": verification_url(cert.certificate_id, request),
    })


def receipt_view(request, receipt_id):
    receipt = get_object_or_404(VerificationReceipt, id=receipt_id)
    return render(request, "receipt.html", {
        "receipt": receipt, "sig_ok": receipt.verify_signature(),
        "cert": receipt.verification.certificate if receipt.verification else None,
    })


def api_verify(request, certificate_id):
    cert = Certificate.objects.filter(certificate_id=certificate_id).first()
    if cert is None:
        return JsonResponse({"found": False, "certificate_id": certificate_id}, status=404)
    return JsonResponse({
        "found": True,
        "certificate_id": cert.certificate_id,
        "holder_name": cert.holder_name,
        "institution": cert.institution.code,
        "award": cert.award,
        "year_of_award": cert.year_of_award,
        "chain_index": cert.chain_index,
        "hash": cert.hash,
        "prev_hash": cert.prev_hash,
        "signature": cert.signature,
        "signed_by_key": cert.signed_by_key,
        "chain_intact": cert.verify_chain(),
        "signature_valid": cert.verify_signature(),
        "revoked": cert.revoked,
        "is_valid": cert.is_valid(),
        "issued_at": cert.issued_at.isoformat(),
    })


def api_chain_status(request):
    total = Certificate.objects.count()
    ok = sum(1 for c in Certificate.objects.all() if c.verify_chain())
    return JsonResponse({
        "total_certificates": total, "intact": ok,
        "tampered": total - ok, "chain_healthy": ok == total,
    })


def api_audit_integrity(request):
    ok, idx = AuditLog.verify_integrity()
    return JsonResponse({
        "audit_log_healthy": ok, "first_tampered_index": idx,
        "total_entries": AuditLog.objects.count(),
    })



def institution_registry(request):
    institutions = Institution.objects.filter(is_active=True).order_by("name")
    return render(request, "institutions.html", {"institutions": institutions})


def revocation_registry(request):
    """Public page showing all revoked certificates."""
    revoked_certs = Certificate.objects.filter(revoked=True).order_by("-revoked_at")
    return render(request, "revocations.html", {"revoked_certs": revoked_certs})

def api_docs(request):
    return render(request, "api_docs.html")

def _client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _save_temp(upload):
    import tempfile, os
    suffix = os.path.splitext(upload.name)[1] or ".png"
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        for chunk in upload.chunks():
            f.write(chunk)
    return path



def revocation_registry(request):
    """Public page showing all revoked certificates."""
    revoked_certs = Certificate.objects.filter(revoked=True).order_by("-revoked_at")
    return render(request, "revocations.html", {"revoked_certs": revoked_certs})

# ==========================================
# CUSTOM ISSUER DASHBOARD (Replaces Django Admin)
# ==========================================
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from .models import Issuer

@login_required
def dashboard(request):
    # Get the institution this user belongs to
    issuer = Issuer.objects.filter(user=request.user).first()
    if not issuer:
        # If they are a superuser but not linked to an issuer, show all
        if request.user.is_superuser:
            certs = Certificate.objects.all().order_by('-issued_at')
            return render(request, "dashboard.html", {"certs": certs, "institution": None})
        return render(request, "dashboard.html", {"error": "You are not assigned to an institution."})

    certs = Certificate.objects.filter(institution=issuer.institution).order_by('-issued_at')
    return render(request, "dashboard.html", {"certs": certs, "institution": issuer.institution})

@login_required
def dashboard_issue(request):
    issuer = Issuer.objects.filter(user=request.user).first()
    if not issuer and not request.user.is_superuser:
        return redirect('core:dashboard')
    
    institutions = Institution.objects.filter(is_active=True) if request.user.is_superuser else [issuer.institution]

    if request.method == "POST":
        data = request.POST
        inst = get_object_or_404(Institution, id=data.get("institution"))
        
        # SECURITY FIX: Strict Validation & Whitelisting
        try:
            year = int(data.get("year_of_award", timezone.now().year))
            if year < 1950 or year > timezone.now().year + 5:
                raise ValueError("Invalid year")
        except ValueError:
            messages.error(request, "Invalid year of award.")
            return redirect('core:dashboard_issue')

        holder_name = data.get("holder_name", "").strip()[:255]
        award = data.get("award", "").strip()[:255]
        
        if not holder_name or not award:
            messages.error(request, "Holder name and award are required.")
            return redirect('core:dashboard_issue')

        # Create the certificate with sanitized data
        cert = Certificate(
            institution=inst,
            holder_name=holder_name,
            holder_id=data.get("holder_id", "").strip()[:50],
            programme=data.get("programme", "").strip()[:255],
            award=award,
            classification=data.get("classification", "").strip()[:100],
            year_of_award=year,
        )
        cert.save()

        # QR & PDF
        verify_url = verification_url(cert.certificate_id, request)
        qr_bytes = generate_qr_png(verify_url)
        cert.qr_code.save(f"{cert.certificate_id}.png", ContentFile(qr_bytes), save=True)

        pdf_bytes = build_certificate_pdf(cert, verify_url)
        cert.pdf_certificate.save(f"{cert.certificate_id}.pdf", ContentFile(pdf_bytes), save=True)

        AuditLog.objects.create(
            action="issue_certificate", actor=request.user,
            target=cert.certificate_id, ip_address=_client_ip(request),
        )
        messages.success(request, f"Successfully issued {cert.certificate_id}")
        return redirect('core:dashboard')

    return render(request, "dashboard_issue.html", {"institutions": institutions})

def custom_login(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('core:dashboard')
    else:
        form = AuthenticationForm()
    return render(request, "login.html", {"form": form})

def custom_logout(request):
    from django.contrib.auth import logout
    logout(request)
    return redirect('core:home')

@login_required
def dashboard_institutions(request):
    if not request.user.is_superuser:
        messages.error(request, "Only superusers can manage institutions.")
        return redirect('core:dashboard')
        
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        code = request.POST.get("code", "").strip().upper()
        email = request.POST.get("email", "").strip()
        
        if Institution.objects.filter(code=code).exists():
            messages.error(request, f"Institution with code {code} already exists.")
        elif name and code:
            # Automatically generates the Ed25519 keypair on save via the model
            inst = Institution(name=name, code=code, email=email)
            # We generate the keys here manually since we aren't in the Django Admin
            from .signing import generate_keypair
            priv, pub = generate_keypair()
            inst._private_key = priv
            inst.public_key = pub
            inst.save()
            messages.success(request, f"Institution {name} added successfully.")
            return redirect('core:dashboard_institutions')
            
    institutions = Institution.objects.all().order_by("-created_at")
    return render(request, "dashboard_institutions.html", {"institutions": institutions})

# ==========================================
# BULK VERIFICATION (HR Tool)
# ==========================================
import csv
import io

@login_required
def bulk_verify(request):
    results = []
    if request.method == "POST":
        csv_file = request.FILES.get("csv_file")
        if not csv_file or not csv_file.name.endswith('.csv'):
            messages.error(request, "Please upload a valid CSV file.")
        else:
            data_set = csv_file.read().decode('UTF-8')
            io_string = io.StringIO(data_set)
            # Read CSV (skip header if it exists)
            reader = csv.reader(io_string, delimiter=',', quotechar='"')
            
            for row in reader:
                if not row: continue
                cert_id = row[0].strip()
                
                # Skip header row if someone includes it
                if cert_id.lower() == "certificate_id" or cert_id.lower() == "id":
                    continue
                    
                cert = Certificate.objects.filter(certificate_id=cert_id).first()
                
                if not cert:
                    results.append({"id": cert_id, "status": "NOT FOUND", "holder": "-", "valid": False, "reason": "Does not exist on ledger"})
                elif cert.revoked:
                    results.append({"id": cert_id, "status": "REVOKED", "holder": cert.holder_name, "valid": False, "reason": "Revoked by institution"})
                elif not cert.verify_chain() or not cert.verify_signature():
                    results.append({"id": cert_id, "status": "TAMPERED", "holder": cert.holder_name, "valid": False, "reason": "Cryptographic proof failed"})
                else:
                    results.append({"id": cert_id, "status": "AUTHENTIC", "holder": cert.holder_name, "valid": True, "reason": "Valid signature & chain"})

    return render(request, "bulk_verify.html", {"results": results})



# ==========================================
# BRUTE FORCE PROTECTION
# ==========================================
from django.core.cache import cache

def custom_login(request):
    if request.method == "POST":
        ip = _client_ip(request)
        attempts = cache.get(f"login_attempts_{ip}", 0)
        
        if attempts >= 5:
            messages.error(request, "Too many failed attempts. Try again in 15 minutes.")
            return render(request, "login.html", {"form": AuthenticationForm()})

        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            cache.delete(f"login_attempts_{ip}") # Reset on success
            return redirect('core:dashboard')
        else:
            cache.set(f"login_attempts_{ip}", attempts + 1, timeout=900) # 15 mins
            messages.error(request, "Invalid username or password.")
            
    return render(request, "login.html", {"form": AuthenticationForm()})

def api_chain_status(request):
    total = Certificate.objects.count()
    # Loop through all certs and verify the hash chain and signatures
    valid_count = 0
    tampered_count = 0
    broken_links = []
    
    certs = Certificate.objects.order_by("chain_index")
    prev_hash = ""
    
    for c in certs:
        if not c.verify_chain() or not c.verify_signature():
            tampered_count += 1
            broken_links.append(c.certificate_id)
        elif c.prev_hash != prev_hash and c.chain_index > 0:
            tampered_count += 1
            broken_links.append(f"{c.certificate_id} (chain link broken)")
        else:
            valid_count += 1
        prev_hash = c.hash

    return JsonResponse({
        "total_certificates": total,
        "valid": valid_count,
        "tampered": tampered_count,
        "chain_healthy": tampered_count == 0,
        "broken_links": broken_links
    })
