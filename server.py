"""
STEGANOGRAPHY DETECTION SERVER v2
Flask server that:
  - Serves the dashboard (index.html + scan_report.json)
  - /scan endpoint: receives uploaded image, runs REAL v2 detection, returns JSON
Run: python server.py
Open: http://localhost:5000
"""

import os
import sys
import tempfile
# pyrefly: ignore [missing-import]
from flask import Flask, request, jsonify, send_from_directory

# ── Import detection functions from detect_steganography.py ──────────────────
sys.path.insert(0, os.path.dirname(__file__))
from detect_steganography import (
    chi_square_attack,
    lsb_uniformity,
    shannon_entropy,
    compression_ratio_score,
    active_steghide_extract,
    lsb_extract_png,
    stegexpose_scan,
    jpeg_verdict,
    png_verdict,
    scan_audio_file
)
import numpy as np
from PIL import Image

app = Flask(__name__, static_folder=".", static_url_path="")

# ── Serve Dashboard ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/scan_report.json")
def scan_report():
    if os.path.exists("scan_report.json"):
        return send_from_directory(".", "scan_report.json")
    return jsonify({"error": "Run detect_steganography.py first"}), 404

@app.route("/download-report")
def download_report():
    """Serve forensic_report.txt as a file download."""
    if os.path.exists("forensic_report.txt"):
        from flask import send_file
        return send_file(
            os.path.abspath("forensic_report.txt"),
            as_attachment=True,
            download_name="forensic_report.txt",
            mimetype="text/plain"
        )
    return jsonify({"error": "Run generate_report.py first"}), 404

@app.route("/report-preview")
def report_preview():
    """Return forensic_report.txt content for in-dashboard preview."""
    if os.path.exists("forensic_report.txt"):
        with open("forensic_report.txt", "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return content, 200, {"Content-Type": "text/plain; charset=utf-8"}
    return "Report not found. Run generate_report.py first.", 404

@app.route("/download-pdf")
def download_pdf():
    """Generate and serve the forensic PDF report."""
    try:
        from generate_pdf_report import generate_pdf
        from flask import send_file
        pdf_path = generate_pdf()
        return send_file(
            os.path.abspath("forensic_report.pdf"),
            as_attachment=True,
            download_name="forensic_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── /scan Endpoint — Real Detection ──────────────────────────────────────────
@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = os.path.splitext(uploaded.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".wav", ".mp3"]:
        return jsonify({"error": "Unsupported format. Use JPG, PNG, WAV, or MP3."}), 400

    # Save to temp file
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    uploaded.save(tmp.name)
    tmp.close()

    # Steghide on Windows CANNOT handle Unicode filenames → copy to ASCII-safe path
    import re, shutil
    safe_tmp_name = re.sub(r'[^\x00-\x7F]', '', tmp.name)  # strip non-ASCII
    if safe_tmp_name != tmp.name:
        shutil.copy2(tmp.name, safe_tmp_name)
        ascii_path = safe_tmp_name
    else:
        ascii_path = tmp.name

    converted_wav = None  # track MP3→WAV temp file

    try:
        # ── MP3 → WAV conversion ──────────────────────────────────
        if ext == ".mp3":
            import miniaudio, wave, struct
            decoded = miniaudio.decode_file(tmp.name,
                          output_format=miniaudio.SampleFormat.SIGNED16,
                          nchannels=1, sample_rate=44100)
            wav_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
            wav_tmp.close()
            converted_wav = wav_tmp.name
            with wave.open(converted_wav, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(44100)
                wf.writeframes(decoded.samples)
            scan_path = converted_wav
            ext = ".wav"  # treat as WAV from here
        else:
            scan_path = ascii_path  # ASCII-safe path for Steghide

        # ── WAV audio ─────────────────────────────────────────────
        if ext == ".wav":
            is_mp3_origin = (converted_wav is not None)  # came from MP3 conversion
            result = scan_audio_file(scan_path, "uploaded-wav")

            # For MP3-origin files: Steghide can't extract from decoded WAV,
            # so rely ONLY on statistical indicators (LSB + Entropy)
            if is_mp3_origin:
                lsb_s   = result["lsb_uniformity_score"]
                ent_s   = result["entropy_score"]
                # MP3 verdict: LSB 60% + Entropy 40% weight, threshold 0.75
                mp3_score = 0.60 * lsb_s + 0.40 * ent_s
                if mp3_score >= 0.75:
                    mp3_verdict  = "STEGO DETECTED"
                    mp3_conf     = round(mp3_score * 100, 1)
                    mp3_reasons  = [
                        f"Audio LSB randomness high ({lsb_s:.2f}) — suspicious bit plane",
                        f"Audio entropy high ({ent_s:.2f}) — random LSB distribution",
                        "NOTE: MP3 file — Steghide extraction not applicable (use MP3Stego/DeepSound to extract)"
                    ]
                else:
                    mp3_verdict  = "CLEAN"
                    mp3_conf     = round(mp3_score * 100, 1)
                    mp3_reasons  = result["reasons"]
                return jsonify({
                    "filename":             uploaded.filename,
                    "file_size_bytes":      os.path.getsize(tmp.name),
                    "chi_square_score":     0.0,
                    "lsb_uniformity_score": lsb_s,
                    "entropy_score":        ent_s,
                    "compression_score":    0.0,
                    "stegexpose_score":     0.0,
                    "steghide_extracted":   False,
                    "extracted_content":    "N/A — MP3 file (use MP3Stego or DeepSound to extract)",
                    "confidence_pct":       mp3_conf,
                    "reasons":              mp3_reasons,
                    "final_verdict":        mp3_verdict
                })

            # Regular WAV file
            return jsonify({
                "filename":             uploaded.filename,
                "file_size_bytes":      os.path.getsize(tmp.name),
                "chi_square_score":     0.0,
                "lsb_uniformity_score": result["lsb_uniformity_score"],
                "entropy_score":        result["entropy_score"],
                "compression_score":    0.0,
                "stegexpose_score":     0.0,
                "steghide_extracted":   result["steghide_extracted"],
                "extracted_content":    result["extracted_content"],
                "confidence_pct":       result["confidence_pct"],
                "reasons":              result["reasons"],
                "final_verdict":        result["final_verdict"]
            })

        # ── Image (JPEG / PNG) — Original v2 Logic ──────────────────
        img    = Image.open(scan_path).convert("RGB")
        arr    = np.array(img).flatten().astype(np.int32)
        pixels = img.width * img.height

        # Run all statistical features
        chi         = chi_square_attack(arr)
        lsb_score   = lsb_uniformity(arr)
        entropy     = shannon_entropy(arr)
        compression = compression_ratio_score(tmp.name, pixels)

        # StegExpose (JPEG only)
        stegexpose = 0.0
        if ext in [".jpg", ".jpeg"]:
            stegexpose = stegexpose_scan(tmp.name)

        # Steghide extraction (JPEG) — brute-forces all PASSWORDS
        extracted, content = False, ""
        png_extracted = False
        if ext in [".jpg", ".jpeg"]:
            extracted, content = active_steghide_extract(tmp.name)
        else:
            # PNG: LSB extraction (no password needed)
            png_extracted, content = lsb_extract_png(tmp.name)

        any_extracted = extracted or png_extracted

        # Verdict using original functions
        if ext in [".jpg", ".jpeg"]:
            v = jpeg_verdict(chi, lsb_score, extracted, stegexpose, entropy)
        else:
            if png_extracted:
                v = {
                    "confidence_score": 100.0,
                    "final_verdict":    "STEGO DETECTED",
                    "reasons":          ["LSB extraction SUCCESS — hidden message recovered (no password needed)"]
                }
            else:
                v = png_verdict(entropy, lsb_score, compression)

        return jsonify({
            "filename":              uploaded.filename,
            "file_size_bytes":       os.path.getsize(tmp.name),
            "chi_square_score":      chi,
            "lsb_uniformity_score":  lsb_score,
            "entropy_score":         entropy,
            "compression_score":     compression,
            "stegexpose_score":      stegexpose,
            "steghide_extracted":    any_extracted,
            "extracted_content":     content if any_extracted else "N/A",
            "confidence_pct":        v["confidence_score"],
            "reasons":               v["reasons"],
            "final_verdict":         v["final_verdict"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  STEGANOGRAPHY DETECTION SERVER v2")
    print("  Real detection: Chi-Square + LSB + Entropy + Steghide")
    print("  Open: http://localhost:5000")
    print("=" * 60)
    app.run(debug=False, port=5000)
