"""Read-only QR dataset inventory. Content hashing is streamed from qr.zip."""
from __future__ import annotations

import hashlib
import json
import re
import statistics
import struct
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "qr.zip"
EXTRACTED = ROOT / "data" / "qr"
OUTPUT = ROOT / "ml" / "reports" / "qr_dataset_audit.json"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}


def summarize(rows: list[dict]) -> dict:
    widths = [x["width"] for x in rows if x.get("width")]
    heights = [x["height"] for x in rows if x.get("height")]
    sizes = [x["bytes"] for x in rows]
    dimensions = Counter(f"{x['width']}x{x['height']}" for x in rows if x.get("width"))
    modes = Counter(x["mode"] for x in rows if x.get("mode"))
    depths = Counter(str(x["bit_depth"]) for x in rows if x.get("bit_depth") is not None)
    colors = Counter(str(x["color_type"]) for x in rows if x.get("color_type") is not None)
    ratios = [x["width"] / x["height"] for x in rows if x.get("width") and x.get("height")]
    return {
        "image_count": len(rows), "png_header_valid_count": sum(x.get("png_header_valid", False) for x in rows),
        "dimensions_counts": dict(sorted(dimensions.items())),
        "width_min_max": [min(widths), max(widths)] if widths else None,
        "height_min_max": [min(heights), max(heights)] if heights else None,
        "aspect_ratio_min_max": [round(min(ratios), 6), round(max(ratios), 6)] if ratios else None,
        "modes_from_png_color_type": dict(sorted(modes.items())),
        "png_bit_depths": dict(sorted(depths.items())), "png_color_types": dict(sorted(colors.items())),
        "transparency_channel_count": sum(x.get("has_transparency", False) for x in rows),
        "file_size_bytes": {"min": min(sizes) if sizes else None,
                             "median": statistics.median(sizes) if sizes else None,
                             "max": max(sizes) if sizes else None},
    }


def main() -> None:
    by_folder: dict[str, list[dict]] = defaultdict(list)
    by_hash: dict[str, list[str]] = defaultdict(list)
    archive_extensions = Counter()
    non_images, duplicate_names = [], []
    seen_names = set()
    archive_size = 0
    total_count = 0
    # ZIP files are sequentially streamed to avoid opening 200k OneDrive-synced files individually.
    with zipfile.ZipFile(ARCHIVE) as archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        for member in members:
            if member.filename in seen_names:
                duplicate_names.append(member.filename)
            seen_names.add(member.filename)
            ext = Path(member.filename).suffix.lower()
            archive_extensions[ext or "[no extension]"] += 1
            if ext not in IMAGE_EXTENSIONS:
                non_images.append(member.filename)
                continue
            total_count += 1
            archive_size += member.file_size
            data = archive.read(member)
            digest = hashlib.sha256(data).hexdigest()
            rel = Path(member.filename).as_posix()
            folder = Path(rel).parent.as_posix()
            row = {"path": rel, "filename": Path(rel).name, "candidate_folder": folder,
                   "extension": ext, "bytes": member.file_size, "sha256": digest,
                   "png_header_valid": False}
            if len(data) >= 26 and data[:8] == b"\x89PNG\r\n\x1a\n":
                width, height = struct.unpack(">II", data[16:24])
                depth, color = data[24], data[25]
                row.update({"width": width, "height": height,
                            "mode": {0: "L", 2: "RGB", 3: "P", 4: "LA", 6: "RGBA"}.get(color, "unknown"),
                            "bit_depth": depth, "color_type": color, "has_transparency": color in (3, 4, 6),
                            "png_header_valid": width > 0 and height > 0})
            by_folder[folder].append(row)
            by_hash[digest].append(rel)

    duplicate_groups = [p for p in by_hash.values() if len(p) > 1]
    duplicate_cross_folder = [p for p in duplicate_groups if len({str(Path(x).parent) for x in p}) > 1]
    folder_report = {}
    for folder, rows in sorted(by_folder.items()):
        nums = [int(Path(x["filename"]).stem.rsplit("_", 1)[-1]) for x in rows
                if Path(x["filename"]).stem.rsplit("_", 1)[-1].isdigit()]
        folder_report[folder] = {"candidate_folder_only_label": True, **summarize(rows),
                                 "filename_index_min_max": [min(nums), max(nums)] if nums else None}

    # Independently enumerate extracted tree; compare selected edge/interior files by bytes/hash.
    extracted_files = [p for p in EXTRACTED.rglob("*") if p.is_file()]
    extracted_images = [p for p in extracted_files if p.suffix.lower() in IMAGE_EXTENSIONS]
    samples = []
    for folder, rows in sorted(by_folder.items()):
        if not rows:
            continue
        selected = [rows[0], rows[len(rows) // 2], rows[-1]]
        for row in selected:
            local = EXTRACTED / Path(row["path"])
            try:
                local_hash = hashlib.sha256(local.read_bytes()).hexdigest()
                samples.append({"path": row["path"], "exists": True, "hash_matches_archive": local_hash == row["sha256"]})
            except OSError as exc:
                samples.append({"path": row["path"], "exists": False, "error": str(exc)})

    payload_samples = []
    try:
        import cv2
        decoder = cv2.QRCodeDetector()
        for folder, rows in sorted(by_folder.items()):
            if not rows:
                continue
            for row in (rows[0], rows[len(rows)//4], rows[len(rows)//2], rows[(3*len(rows))//4], rows[-1]):
                image = cv2.imread(str(EXTRACTED / Path(row["path"])))
                payload, _, _ = decoder.detectAndDecode(image) if image is not None else ("", None, None)
                urls = re.findall(r"https?://[^\s'\"]+", payload)
                payload_samples.append({"path": row["path"], "decoded": bool(payload),
                    "payload_format": "indexed pandas Series text" if "Name: url, dtype: object" in payload else ("URL/text" if payload else "undecodable"),
                    "url_host": urlsplit(urls[0]).hostname if urls else None})
    except ImportError:
        payload_samples = None

    all_local_ext = Counter(p.suffix.lower() or "[no extension]" for p in extracted_files)
    report = {
        "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "audit_scope": "read-only; folder names are candidate categories, not validated ground-truth labels",
        "locations": {"archive": str(ARCHIVE), "extracted_copy": str(EXTRACTED)},
        "zip_inventory": {"project_root_zip_files": sorted(p.name for p in ROOT.glob("*.zip")),
                          "qr_related_zip_files": sorted(p.name for p in ROOT.glob("*.zip") if "qr" in p.name.lower()),
                          "qr_related_zip_count": sum("qr" in p.name.lower() for p in ROOT.glob("*.zip"))},
        "archive": {"size_bytes": ARCHIVE.stat().st_size, "member_count": len(members),
                    "image_count": total_count, "image_uncompressed_bytes": archive_size,
                    "extensions": dict(sorted(archive_extensions.items())), "non_image_or_metadata_files": non_images,
                    "duplicate_member_name_count": len(duplicate_names), "duplicate_member_names": duplicate_names,
                    "exact_duplicate_sha256_groups": len(duplicate_groups),
                    "duplicate_image_count_excess": sum(len(x)-1 for x in duplicate_groups),
                    "cross_candidate_folder_duplicate_groups": len(duplicate_cross_folder),
                    "cross_candidate_folder_duplicate_examples": duplicate_cross_folder[:20]},
        "extracted_copy": {"file_count_all_types": len(extracted_files), "image_count": len(extracted_images),
                           "extensions": dict(sorted(all_local_ext.items())),
                           "candidate_folder_counts": {k: len(v) for k, v in sorted(by_folder.items())},
                           "sample_archive_matches": samples},
        "candidate_folders": folder_report,
        "semantic_findings": {"folder_names_are_ground_truth": False,
                              "verified_genuine_vs_tampered_metadata_found": False,
                              "label_interpretation": "No label documentation or metadata is present in the archive; benign/malicious does not establish genuine/tampered.",
                              "payload_vs_visual_tampering": "The representative decoded payloads are URLs; folder semantics suggest destination reputation, not visual manipulation, but source documentation is unavailable."},
        "representative_payload_decode": {"decoder": "OpenCV QRCodeDetector" if payload_samples is not None else None,
                                          "sample_count": len(payload_samples) if payload_samples is not None else 0,
                                          "decoded_count": sum(x["decoded"] for x in payload_samples) if payload_samples is not None else None,
                                          "samples": payload_samples},
        "representative_visual_observations": "Contact sheet contains high-contrast black-and-white QR codes with no obvious overlays or visible manipulation in the inspected examples. This is a sample-only visual observation, not a tampering label.",
        "limitations": ["Archive image inventory, PNG header stats, and SHA-256 duplicate scan are exhaustive.",
                        "Extracted-copy identity was checked on three deterministic samples per candidate folder, not all files.",
                        "PNG header parsing is not full pixel decoding; representative samples are visually/decode checked separately.",
                        "Near-duplicate search and all-image payload decoding were not run."],
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    print(f"Archive images: {total_count}; folders: {len(by_folder)}; exact duplicate groups: {len(duplicate_groups)}")
    print(f"Extracted images: {len(extracted_images)}; representative matches: {sum(x.get('hash_matches_archive', False) for x in samples)}/{len(samples)}")


if __name__ == "__main__":
    main()
