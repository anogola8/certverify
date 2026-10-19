"""
Offline Verification Tool for CertVerify.
This script can be run on any computer to verify a certificate WITHOUT 
connecting to the CertVerify database. It uses pure Ed25519 cryptography.

Usage:
python offline_verify.py <certificate_id> <holder_name> <institution_code> <prev_hash> <hash> <signature> <public_key>
"""
import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

def verify_offline(cert_id, holder_name, inst_code, prev_hash, cert_hash, signature_b64, public_key_b64):
    print(f"\n--- Offline Verification Report ---")
    print(f"Certificate ID: {cert_id}")
    print(f"Holder: {holder_name}")
    print(f"Institution: {inst_code}")
    
    # 1. Recompute the Hash
    # The payload must match EXACTLY how the Django model built it.
    # (Note: We use empty strings for fields not passed in the script for simplicity)
    payload = "|".join([
        cert_id,
        inst_code,
        holder_name,
        "", # holder_id (omitted for CLI simplicity)
        "", # programme (omitted)
        "", # award (omitted)
        "", # classification (omitted)
        "2024", # year_of_award (hardcoded for demo, in production pass as arg)
        prev_hash or "GENESIS",
    ])
    
    computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    
    print(f"\n[1] Recomputing Hash...")
    if computed_hash == cert_hash:
        print(f"    ✅ HASH MATCHES: {computed_hash[:20]}...")
    else:
        print(f"    ❌ HASH MISMATCH!")
        print(f"    Expected (from cert): {cert_hash}")
        print(f"    Computed (by script): {computed_hash}")
        return False

    # 2. Verify the Signature
    print(f"\n[2] Verifying Ed25519 Signature...")
    try:
        # Decode base64 keys
        pub_bytes = base64.urlsafe_b64decode(public_key_b64.encode())
        sig_bytes = base64.urlsafe_b64decode(signature_b64.encode())
        
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        
        # The signature was generated over the cert_hash
        public_key.verify(sig_bytes, cert_hash.encode("utf-8"))
        print(f"    ✅ SIGNATURE VALID: Signed by {inst_code}'s private key.")
        
    except Exception as e:
        print(f"    ❌ SIGNATURE INVALID: {str(e)}")
        return False
        
    print("\n===================================")
    print("🎉 RESULT: CERTIFICATE IS AUTHENTIC")
    print("===================================\n")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 8:
        print("Usage: python offline_verify.py <cert_id> <holder_name> <inst_code> <prev_hash> <hash> <signature> <public_key>")
        sys.exit(1)
        
    verify_offline(*sys.argv[1:8])
