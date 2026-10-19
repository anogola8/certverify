from django.urls import path
from . import views

app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path("verify/", views.verify_upload, name="verify_upload"),
    path("verify/<str:certificate_id>/", views.verify_view, name="verify"),
    
    # THIS WAS THE MISSING LINE:
    path("certificate/<str:certificate_id>/", views.certificate_detail, name="certificate_detail"),
    
    path("receipt/<uuid:receipt_id>/", views.receipt_view, name="receipt"),
    path("institutions/", views.institution_registry, name="institutions"),
    path("revocations/", views.revocation_registry, name="revocations"),
    path("api/docs/", views.api_docs, name="api_docs"),
    path("api/v1/verify/<str:certificate_id>/", views.api_verify, name="api_verify"),
    path("api/v1/chain/", views.api_chain_status, name="api_chain"),
    path("api/v1/audit/integrity/", views.api_audit_integrity, name="api_audit_integrity"),
    
    # Bulk Verify
    path("bulk-verify/", views.bulk_verify, name="bulk_verify"),
    
    # Custom Auth & Dashboard
    path("login/", views.custom_login, name="login"),
    path("logout/", views.custom_logout, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("dashboard/issue/", views.dashboard_issue, name="dashboard_issue"),
    path("dashboard/institutions/", views.dashboard_institutions, name="dashboard_institutions"),
]
