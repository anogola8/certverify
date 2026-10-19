import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "certverify.settings")
django.setup()

from core.models import Certificate

c = Certificate.objects.latest('issued_at')
cmd = f'python core/offline_verify.py {c.certificate_id} "{c.holder_name}" {c.institution.code} "{c.prev_hash}" "{c.hash}" "{c.signature}" "{c.institution.public_key}"'
print("\n--- COPY THIS COMMAND ---\n")
print(cmd)
print("\n-------------------------\n")
