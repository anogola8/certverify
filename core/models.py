import hashlib
import uuid

from django.contrib.auth.models import User
from django.db import models
from simple_history.models import HistoricalRecords


class Institution(models.Model):
    name = models.CharField(max_length=255, unique=True)
    code = models.CharField(max_length=20, unique=True, help_text="Short code, e.g. UON, KU")
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=20, blank=True)
    is_active = models.BooleanField(default=True)

    public_key = models.CharField(max_length=200, blank=True)
    _private_key = models.CharField(max_length=200, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.code} - {self.name}"


class Issuer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    institution = models.ForeignKey(Institution, on_delete=models.CASCADE, related_name="issuers")
    role = models.CharField(max_length=100, default="Registrar")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} @ {self.institution.code}"


class Certificate(models.Model):
    """Append-only hash-chained certificate ledger with Ed25519 signatures."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate_id = models.CharField(max_length=40, unique=True, db_index=True)
    institution = models.ForeignKey(Institution, on_delete=models.PROTECT, related_name="certificates")

    holder_name = models.CharField(max_length=255)
    holder_id = models.CharField(max_length=50, blank=True)
    programme = models.CharField(max_length=255)
    award = models.CharField(max_length=255)
    classification = models.CharField(max_length=100, blank=True)
    year_of_award = models.PositiveIntegerField()
    issued_at = models.DateTimeField(auto_now_add=True)

    prev_hash = models.CharField(max_length=64, blank=True)
    hash = models.CharField(max_length=64, unique=True, db_index=True)
    chain_index = models.PositiveIntegerField(unique=True)

    signature = models.CharField(max_length=200, blank=True)
    signed_by_key = models.CharField(max_length=200, blank=True)

    document = models.FileField(upload_to="certificates/", blank=True, null=True)
    qr_code = models.ImageField(upload_to="qrcodes/", blank=True, null=True)
    pdf_certificate = models.FileField(upload_to="certificates/pdf/", blank=True, null=True)

    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.TextField(blank=True)

    history = HistoricalRecords()

    class Meta:
        ordering = ["chain_index"]

    def _compute_hash(self) -> str:
        payload = "|".join([
            self.certificate_id,
            self.institution.code,
            self.holder_name,
            self.holder_id,
            self.programme,
            self.award,
            self.classification,
            str(self.year_of_award),
            self.prev_hash or "GENESIS",
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def save(self, *args, **kwargs):
        if not self.hash:
            last = Certificate.objects.order_by("-chain_index").first()
            if last:
                self.prev_hash = last.hash
                self.chain_index = last.chain_index + 1
            else:
                self.prev_hash = ""
                self.chain_index = 0

            if not self.certificate_id:
                self.certificate_id = f"CV-{self.institution.code}-{self.chain_index:06d}"

            self.hash = self._compute_hash()

            if self.institution._private_key and not self.signature:
                from .signing import sign_hash
                self.signature = sign_hash(self.institution._private_key, self.hash)
                self.signed_by_key = self.institution.public_key

        super().save(*args, **kwargs)

    def verify_chain(self) -> bool:
        return self._compute_hash() == self.hash

    def verify_signature(self) -> bool:
        if not self.signature or not self.signed_by_key:
            return False
        from .signing import verify_signature
        return verify_signature(self.signed_by_key, self.hash, self.signature)

    def is_valid(self) -> bool:
        return (
            not self.revoked
            and self.verify_chain()
            and self.verify_signature()
        )

    def __str__(self):
        return f"{self.certificate_id} - {self.holder_name}"


class VerificationRequest(models.Model):
    MODE_CHOICES = [
        ("hash", "Hash Lookup"),
        ("forensic", "Forensic Analysis"),
    ]
    RESULT_CHOICES = [
        ("authentic", "Authentic"),
        ("not_found", "Not Found"),
        ("tampered", "Tampered"),
        ("revoked", "Revoked"),
        ("inconclusive", "Inconclusive"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mode = models.CharField(max_length=20, choices=MODE_CHOICES)
    certificate = models.ForeignKey(Certificate, null=True, blank=True, on_delete=models.SET_NULL)
    queried_id = models.CharField(max_length=40, blank=True)
    uploaded_file = models.FileField(upload_to="verifications/", blank=True, null=True)
    result = models.CharField(max_length=20, choices=RESULT_CHOICES)
    confidence = models.FloatField(default=0.0)
    notes = models.TextField(blank=True)
    verifier_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.mode} -> {self.result} ({self.confidence:.2f})"


class ForensicReport(models.Model):
    verification = models.OneToOneField(
        VerificationRequest, on_delete=models.CASCADE, related_name="forensic_report",
    )
    ela_score = models.FloatField(default=0.0)
    metadata_ok = models.BooleanField(default=True)
    metadata_notes = models.TextField(blank=True)
    copy_move_score = models.FloatField(default=0.0)
    font_anomaly_score = models.FloatField(default=0.0)
    ela_image = models.ImageField(upload_to="forensics/ela/", blank=True, null=True)
    overlay_image = models.ImageField(upload_to="forensics/overlay/", blank=True, null=True)
    overall_confidence = models.FloatField(default=0.0)
    raw_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ForensicReport {self.verification.id}"


class AuditLog(models.Model):
    action = models.CharField(max_length=100)
    actor = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    target = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    prev_hmac = models.CharField(max_length=64, blank=True)
    hmac = models.CharField(max_length=64, blank=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    history = HistoricalRecords()

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.hmac:
            last = AuditLog.objects.order_by("-id").first()
            self.prev_hmac = last.hmac if last else ""
            self.hmac = self._compute_hmac()
        super().save(*args, **kwargs)

    def _compute_hmac(self) -> str:
        import hmac as _hmac
        import hashlib as _hashlib
        from django.conf import settings

        secret = settings.SECRET_KEY.encode("utf-8")
        payload = "|".join([
            self.action,
            str(self.actor_id or ""),
            self.target,
            str(self.ip_address or ""),
            self.user_agent,
            str(sorted(self.metadata.items())) if self.metadata else "",
            self.prev_hmac or "GENESIS",
        ])
        return _hmac.new(secret, payload.encode("utf-8"), _hashlib.sha256).hexdigest()

    @staticmethod
    def verify_integrity():
        """Return (ok, first_break_index)."""
        import hmac as _hmac
        import hashlib as _hashlib
        from django.conf import settings

        prev = ""
        for i, entry in enumerate(AuditLog.objects.order_by("id")):
            payload = "|".join([
                entry.action,
                str(entry.actor_id or ""),
                entry.target,
                str(entry.ip_address or ""),
                entry.user_agent,
                str(sorted(entry.metadata.items())) if entry.metadata else "",
                prev,
            ])
            expected = _hmac.new(
                settings.SECRET_KEY.encode("utf-8"),
                payload.encode("utf-8"),
                _hashlib.sha256,
            ).hexdigest()
            if expected != entry.hmac:
                return False, i
            prev = entry.hmac
        return True, -1

    def __str__(self):
        return f"{self.created_at} - {self.action}"


class VerificationReceipt(models.Model):
    """
    A signed proof that CertVerify analyzed a specific document file at a
    specific time.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    verification = models.OneToOneField(
        VerificationRequest, on_delete=models.CASCADE, related_name="receipt",
    )
    document_fingerprint = models.CharField(
        max_length=64, db_index=True,
        help_text="SHA-256 of the uploaded document bytes",
    )
    verdict = models.CharField(max_length=20)
    confidence = models.FloatField()
    issued_at = models.DateTimeField(auto_now_add=True)

    signature = models.CharField(max_length=200, blank=True)
    signed_by_key = models.CharField(max_length=200, blank=True)

    pdf_file = models.FileField(upload_to="receipts/", blank=True, null=True)

    class Meta:
        ordering = ["-issued_at"]

    def __str__(self):
        return f"Receipt {self.id} -> {self.verdict}"

    def verify_signature(self) -> bool:
        if not self.signature or not self.signed_by_key:
            return False
        from .signing import verify_signature
        payload = self._signing_payload()
        return verify_signature(self.signed_by_key, payload, self.signature)

    def _signing_payload(self) -> str:
        return "|".join([
            str(self.id),
            str(self.verification_id),
            self.document_fingerprint,
            self.verdict,
            f"{self.confidence:.6f}",
        ])
