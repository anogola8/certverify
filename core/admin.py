from django.contrib import admin
from simple_history.admin import SimpleHistoryAdmin

from .models import (
    Institution,
    Issuer,
    Certificate,
    VerificationRequest,
    ForensicReport,
    AuditLog,
)


@admin.register(Institution)
class InstitutionAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "is_active", "has_key", "created_at")
    search_fields = ("code", "name")
    readonly_fields = ("public_key", "_private_key")

    def has_key(self, obj):
        return bool(obj._private_key)
    has_key.boolean = True
    has_key.short_description = "Keypair"

    def save_model(self, request, obj, form, change):
        if not obj._private_key:
            from .signing import generate_keypair
            priv, pub = generate_keypair()
            obj._private_key = priv
            obj.public_key = pub
        super().save_model(request, obj, form, change)


@admin.register(Issuer)
class IssuerAdmin(admin.ModelAdmin):
    list_display = ("user", "institution", "role")
    list_filter = ("institution",)


@admin.register(Certificate)
class CertificateAdmin(SimpleHistoryAdmin):
    list_display = (
        "certificate_id", "holder_name", "institution",
        "award", "year_of_award", "chain_index",
        "is_signed", "is_revoked",
    )
    list_filter = ("institution", "year_of_award", "revoked")
    search_fields = ("certificate_id", "holder_name", "holder_id")
    readonly_fields = (
        "hash", "prev_hash", "chain_index", "certificate_id", "issued_at",
        "signature", "signed_by_key",
    )
    actions = ["revoke_certificates"]

    def is_signed(self, obj):
        return bool(obj.signature)
    is_signed.boolean = True
    is_signed.short_description = "Signed"

    def is_revoked(self, obj):
        return obj.revoked
    is_revoked.boolean = True
    is_revoked.short_description = "Revoked"

    @admin.action(description="Revoke selected certificates")
    def revoke_certificates(self, request, queryset):
        from django.utils import timezone
        for cert in queryset.filter(revoked=False):
            cert.revoked = True
            cert.revoked_at = timezone.now()
            cert.revoked_reason = f"Revoked by {request.user.username} via admin"
            cert.save(update_fields=["revoked", "revoked_at", "revoked_reason"])


@admin.register(VerificationRequest)
class VerificationRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "mode", "result", "confidence", "created_at")
    list_filter = ("mode", "result")


@admin.register(ForensicReport)
class ForensicReportAdmin(admin.ModelAdmin):
    list_display = ("verification", "ela_score", "copy_move_score", "overall_confidence", "created_at")


@admin.register(AuditLog)
class AuditLogAdmin(SimpleHistoryAdmin):
    list_display = ("action", "actor", "target", "ip_address", "created_at")
    list_filter = ("action",)
    readonly_fields = ("prev_hmac", "hmac")
