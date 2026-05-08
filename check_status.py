import sys, os, subprocess, tempfile, json
sys.path.insert(0, '.')
from detect_steganography import PASSWORDS, STEGHIDE_EXE

print("=== SYSTEM STATUS CHECK ===\n")

# 1. Passwords
print("[1] PASSWORDS:", PASSWORDS)

# 2. scan_report.json
if os.path.exists("scan_report.json"):
    with open("scan_report.json") as f:
        data = json.load(f)
    s = data["summary"]
    total = s["total_files_scanned"]
    tp    = s["true_positives"]
    acc   = s["overall_accuracy_pct"]
    rate  = s["detection_rate_pct"]
    print(f"[2] scan_report.json: {total} files | TP={tp} | DetRate={rate}% | Acc={acc}%")
else:
    print("[2] scan_report.json: NOT FOUND — run detect_steganography.py")

# 3. Extraction test
print("\n[3] Extraction Tests:")
tests = [
    "stego_dataset/jpeg_steghide/stego_download.jpeg",
    "stego_dataset/audio_steghide/stego_voice_sample_1.wav",
    "stego_dataset/audio_steghide/stego_music_sample_1.wav",
]
for fpath in tests:
    if not os.path.exists(fpath):
        print("    MISSING:", fpath)
        continue
    found = False
    for pwd in PASSWORDS:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as t:
            out = t.name
        r = subprocess.run(
            [STEGHIDE_EXE, "extract", "-sf", fpath, "-p", pwd, "-xf", out, "-f"],
            capture_output=True, text=True, timeout=10
        )
        if os.path.exists(out):
            c = open(out, errors="replace").read().strip()
            os.unlink(out)
            if c:
                print(f"    OK [{pwd}] {os.path.basename(fpath)}: {c[:60]}")
                found = True
                break
    if not found:
        print("    FAIL:", os.path.basename(fpath))

# 4. Core files
print("\n[4] Core Files:")
for ff in ["server.py", "index.html", "style.css", "app.js",
           "generate_pdf_report.py", "detect_steganography.py"]:
    status = "OK" if os.path.exists(ff) else "MISSING"
    print(f"    {status}: {ff}")

print("\n=== DONE ===")
