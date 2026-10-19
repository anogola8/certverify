"""
Forensic analysis for CertVerify.

Three independent checks, each returning a score in [0, 1] where
higher = more suspicious:

  1. ELA (Error Level Analysis) — recompression residue differences.
  2. Metadata inspection — EXIF anomalies, editing-software tags.
  3. Copy-move detection — ORB keypoint clusters suggesting duplication.

The public entry point is `analyze(file_path)`, which returns a dict
suitable for storing in ForensicReport.raw_json and rendering on the
verification result page.
"""

from __future__ import annotations

import io
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

import cv2
import numpy as np
from PIL import Image, ExifTags
import exifread


# --------------------------------------------------------------------------- #
#  Data containers
# --------------------------------------------------------------------------- #

@dataclass
class ELAResult:
    score: float = 0.0
    hotspots: list = field(default_factory=list)   # [(x, y, w, h, intensity), ...]
    ela_image_bytes: Optional[bytes] = None
    notes: str = ""


@dataclass
class MetadataResult:
    score: float = 0.0
    ok: bool = True
    notes: str = ""
    tags: dict = field(default_factory=dict)


@dataclass
class CopyMoveResult:
    score: float = 0.0
    matches: list = field(default_factory=list)    # [(x1, y1, x2, y2), ...]
    overlay_bytes: Optional[bytes] = None
    notes: str = ""


# --------------------------------------------------------------------------- #
#  1. Error Level Analysis
# --------------------------------------------------------------------------- #

def _ela(image_path: str, quality: int = 90) -> ELAResult:
    """
    Re-save the image at a known JPEG quality, diff against the original,
    and amplify the difference. Regions that were edited after the original
    save will light up brighter than the untouched background.
    """
    try:
        original = Image.open(image_path).convert("RGB")
    except Exception as e:
        return ELAResult(score=0.0, notes=f"Could not open image: {e}")

    # Re-encode to a buffer
    buf = io.BytesIO()
    original.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    recompressed = Image.open(buf).convert("RGB")

    # Absolute difference, scaled for visibility
    diff = np.abs(
        np.asarray(original, dtype=np.int16)
        - np.asarray(recompressed, dtype=np.int16)
    ).astype(np.uint8)

    # Amplify the difference (ELA classic uses 10-20x)
    ela = np.clip(diff * 15, 0, 255).astype(np.uint8)
    ela_gray = cv2.cvtColor(ela, cv2.COLOR_RGB2GRAY)

    # Score: fraction of pixels with unusually high residual
    threshold = ela_gray.mean() + 2 * ela_gray.std()
    hot_mask = (ela_gray > threshold).astype(np.uint8) * 255
    hot_ratio = float(hot_mask.sum() / 255) / hot_mask.size

    # Find connected hotspots as bounding boxes
    num, labels, stats, _ = cv2.connectedComponentsWithStats(hot_mask, connectivity=8)
    hotspots = []
    for i in range(1, num):
        x, y, w, h, area = stats[i]
        if area < 200:            # ignore specks
            continue
        hotspots.append((int(x), int(y), int(w), int(h), float(area)))
    hotspots.sort(key=lambda h: -h[4])
    hotspots = hotspots[:10]

    # Encode the ELA image as PNG bytes for storage
    ok, png = cv2.imencode(".png", cv2.cvtColor(ela, cv2.COLOR_RGB2BGR))
    ela_bytes = png.tobytes() if ok else None

    # Normalise score: 0.02 hot ratio is already suspicious, 0.2 is very high
    score = min(1.0, hot_ratio / 0.2)

    note = (
        f"High-residual area covers {hot_ratio * 100:.1f}% of the image. "
        f"{len(hotspots)} region(s) flagged."
    )
    return ELAResult(score=score, hotspots=hotspots, ela_image_bytes=ela_bytes, notes=note)


# --------------------------------------------------------------------------- #
#  2. Metadata inspection
# --------------------------------------------------------------------------- #

_SUSPICIOUS_SOFTWARE = {
    "photoshop", "gimp", "affinity", "pixelmator",
    "lightroom", "inkscape", "illustrator",
}


def _metadata(image_path: str) -> MetadataResult:
    tags: dict = {}
    score = 0.0
    notes = []

    # Pillow-level EXIF
    try:
        img = Image.open(image_path)
        exif = img.getexif()
        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            tags[tag] = str(value)[:200]
    except Exception as e:
        notes.append(f"EXIF read failed: {e}")

    # exifread gives richer output
    try:
        with open(image_path, "rb") as f:
            raw = exifread.process_file(f, details=False)
        for k, v in raw.items():
            if k not in ("JPEGThumbnail", "TIFFThumbnail"):
                tags.setdefault(k, str(v)[:200])
    except Exception as e:
        notes.append(f"exifread failed: {e}")

    # Check software tag
    software_candidates = [
        tags.get("Software", ""),
        tags.get("Image Software", ""),
        tags.get("EXIF Software", ""),
    ]
    software_str = " ".join(software_candidates).lower()
    for bad in _SUSPICIOUS_SOFTWARE:
        if bad in software_str:
            score = max(score, 0.8)
            notes.append(f"Editing software tag detected: '{bad}'.")
            break

    # Missing DateTimeOriginal is unusual for a scanned cert
    has_datetime = any("DateTime" in k for k in tags)
    if not has_datetime:
        score = max(score, 0.3)
        notes.append("No DateTime tag found — original capture date unknown.")

    # JPEG made by a camera vs. edited — look for Make/Model
    has_camera = "Make" in tags or "Image Make" in tags
    if not has_camera:
        score = max(score, 0.2)
        notes.append("No camera Make tag — image may be a re-render or screenshot.")

    ok = score < 0.5
    return MetadataResult(
        score=score,
        ok=ok,
        notes=" ".join(notes) if notes else "Metadata appears consistent.",
        tags=tags,
    )


# --------------------------------------------------------------------------- #
#  3. Copy-move detection (ORB + ratio test)
# --------------------------------------------------------------------------- #

def _copy_move(image_path: str, max_features: int = 2000) -> CopyMoveResult:
    """
    ORB keypoints matched against themselves. Pairs that are far apart in
    the image but have near-identical descriptors are strong copy-move signals.
    """
    img = cv2.imread(image_path)
    if img is None:
        return CopyMoveResult(score=0.0, notes="Could not read image with OpenCV.")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    orb = cv2.ORB_create(nfeatures=max_features)
    kp, des = orb.detectAndCompute(gray, None)
    if des is None or len(kp) < 20:
        return CopyMoveResult(score=0.0, notes="Too few keypoints for copy-move analysis.")

    # Brute-force Hamming matcher, keep only very close matches
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    matches = bf.knnMatch(des, des, k=3)

    suspicious = []
    h, w = gray.shape
    diag = float(np.hypot(h, w))
    for group in matches:
        # group[0] is the self-match; skip it. Compare group[1] and group[2]
        if len(group) < 3:
            continue
        m1, m2 = group[1], group[2]
        if m1.distance > 40 or m2.distance > 40:
            continue
        p1 = kp[m1.queryIdx].pt
        p2 = kp[m1.trainIdx].pt
        dist = float(np.hypot(p1[0] - p2[0], p1[1] - p2[1]))
        # Matches that are close together are self-similarity noise; we want
        # pairs that are FAR apart but descriptor-similar (copy-paste).
        if dist < diag * 0.25:
            continue
        suspicious.append((int(p1[0]), int(p1[1]), int(p2[0]), int(p2[1])))

    overlay_bytes = None
    if suspicious:
        overlay = img.copy()
        for (x1, y1, x2, y2) in suspicious[:30]:
            cv2.line(overlay, (x1, y1), (x2, y2), (0, 0, 255), 2)
            cv2.circle(overlay, (x1, y1), 4, (0, 255, 0), -1)
            cv2.circle(overlay, (x2, y2), 4, (0, 255, 255), -1)
        ok, png = cv2.imencode(".png", overlay)
        overlay_bytes = png.tobytes() if ok else None

    # Score: how many suspicious pairs relative to a soft cap
    score = min(1.0, len(suspicious) / 30.0)
    notes = f"{len(suspicious)} potential copy-move pair(s) detected."
    return CopyMoveResult(score=score, matches=suspicious[:30], overlay_bytes=overlay_bytes, notes=notes)


# --------------------------------------------------------------------------- #
#  Public entry point
# --------------------------------------------------------------------------- #

def analyze(file_path: str) -> dict:
    """
    Run all three checks and return a JSON-serialisable report.

    Keys:
      ela_score, copy_move_score, metadata_score
      overall_confidence (0–1, higher = more suspicious)
      verdict ("authentic" | "inconclusive" | "tampered")
      notes — human-readable summary
      ela_image_bytes / overlay_bytes — PNG blobs (not JSON-safe; caller saves them)
      raw — full nested result for storage
    """
    ela = _ela(file_path)
    meta = _metadata(file_path)
    cm = _copy_move(file_path)

    # Weighted overall suspicion score
    overall = round(
        0.5 * ela.score + 0.3 * cm.score + 0.2 * meta.score,
        3,
    )

    if overall < 0.25:
        verdict = "authentic"
    elif overall < 0.55:
        verdict = "inconclusive"
    else:
        verdict = "tampered"

    notes_lines = [
        f"ELA: {ela.notes}",
        f"Metadata: {meta.notes}",
        f"Copy-move: {cm.notes}",
        f"Overall suspicion: {overall:.2f} → {verdict}",
    ]

    return {
        "ela_score": round(ela.score, 3),
        "copy_move_score": round(cm.score, 3),
        "metadata_score": round(meta.score, 3),
        "overall_confidence": overall,
        "verdict": verdict,
        "notes": "\n".join(notes_lines),
        "metadata_ok": meta.ok,
        "ela_image_bytes": ela.ela_image_bytes,
        "overlay_bytes": cm.overlay_bytes,
        "raw": {
            "ela": {"score": ela.score, "hotspots": ela.hotspots},
            "metadata": {"score": meta.score, "tags": meta.tags, "ok": meta.ok},
            "copy_move": {"score": cm.score, "matches": cm.matches},
        },
    }


# --------------------------------------------------------------------------- #
#  CLI self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import sys, pprint
    if len(sys.argv) < 2:
        print("Usage: python -m core.forensics <image_path>")
        sys.exit(1)
    result = analyze(sys.argv[1])
    printable = {k: v for k, v in result.items() if not k.endswith("_bytes")}
    pprint.pprint(printable)