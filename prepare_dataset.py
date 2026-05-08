"""
STEP 1 — Dataset Preparation
Steganography Detection and Hidden Data Extraction Project

Three embedding techniques:
  1. Steghide  → JPEG files (via subprocess, non-interactive)
  2. LSB       → PNG files  (via Python/Pillow)
  3. Steghide  → WAV audio files (Steghide natively supports WAV)
"""

import os
import struct
import subprocess
import wave
import math
import numpy as np
from PIL import Image

# ── Paths ────────────────────────────────────────────────────────────────────
STEGHIDE_EXE    = r".\steghide-0.5.1-win32\steghide\steghide.exe"
SECRET_FILE     = r"clean_dataset\secret_message.txt"
JPEG_CLEAN_DIR  = r"clean_dataset\jpeg"
PNG_CLEAN_DIR   = r"clean_dataset\png"
AUDIO_CLEAN_DIR = r"clean_dataset\audio_wav"
JPEG_STEGO_DIR  = r"stego_dataset\jpeg_steghide"
PNG_STEGO_DIR   = r"stego_dataset\png_lsb"
AUDIO_STEGO_DIR = r"stego_dataset\audio_steghide"
PASSWORD1 = "stego123"      # primary password
PASSWORD2 = "stegopass123"  # secondary password (brute-force demo)

os.makedirs(JPEG_STEGO_DIR,  exist_ok=True)
os.makedirs(PNG_STEGO_DIR,   exist_ok=True)
os.makedirs(AUDIO_CLEAN_DIR, exist_ok=True)
os.makedirs(AUDIO_STEGO_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 1: Steghide Embedding for JPEG
# Non-interactive: password passed directly via -p flag
# ─────────────────────────────────────────────────────────────────────────────
def embed_steghide(cover_path: str, output_path: str, password: str = PASSWORD1):
    cmd = [
        STEGHIDE_EXE, "embed",
        "-cf", cover_path,
        "-ef", SECRET_FILE,
        "-sf", output_path,
        "-p",  password,
        "-f"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 2: LSB Embedding for PNG
# Hides secret bytes in the Least Significant Bit of each pixel channel
# ─────────────────────────────────────────────────────────────────────────────
def embed_lsb(cover_path: str, output_path: str, secret_path: str):
    with open(secret_path, "rb") as f:
        secret_bytes = f.read()

    img = Image.open(cover_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)

    # Prepend 4-byte length header so extraction knows when to stop
    payload = struct.pack(">I", len(secret_bytes)) + secret_bytes
    bits    = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    flat = pixels.flatten()
    if len(bits) > len(flat):
        raise ValueError(f"Image too small: needs {len(bits)} pixels, has {len(flat)}")

    # Replace LSB of each pixel value with one payload bit
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    stego = flat.reshape(pixels.shape)
    Image.fromarray(stego, "RGB").save(output_path)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  STEP 1 — DATASET PREPARATION")
    print("=" * 60)

    # ── JPEG via Steghide ──────────────────────────────────────────
    print("\n[TECHNIQUE 1] Steghide — embedding into JPEG files...")
    jpeg_files = [f for f in os.listdir(JPEG_CLEAN_DIR) if f.lower().endswith((".jpg", ".jpeg"))]
    jpeg_ok = 0
    # Split: first half with stego123, second half with stegopass123
    half = len(jpeg_files) // 2
    for i, fname in enumerate(jpeg_files):
        pwd    = PASSWORD1 if i < half else PASSWORD2
        cover  = os.path.join(JPEG_CLEAN_DIR, fname)
        output = os.path.join(JPEG_STEGO_DIR, f"stego_{fname}")
        ok = embed_steghide(cover, output, pwd)
        status = "OK" if ok else "FAILED"
        print(f"  [{status}] {fname} -> stego_{fname}  [pwd: {pwd}]")
        if ok:
            jpeg_ok += 1

    # ── PNG via LSB ────────────────────────────────────────────────
    print("\n[TECHNIQUE 2] LSB Substitution — embedding into PNG files...")
    png_files = [f for f in os.listdir(PNG_CLEAN_DIR) if f.lower().endswith(".png")]
    png_ok = 0
    for fname in png_files:
        cover  = os.path.join(PNG_CLEAN_DIR, fname)
        output = os.path.join(PNG_STEGO_DIR, f"stego_{fname}")
        try:
            embed_lsb(cover, output, SECRET_FILE)
            print(f"  [OK] {fname} -> stego_{fname}")
            png_ok += 1
        except Exception as e:
            print(f"  [FAILED] {fname}: {e}")

    # ── TECHNIQUE 3: Steghide Embedding for WAV Audio ─────────────────────────
    print("\n[TECHNIQUE 3] Steghide — embedding into WAV audio files...")

    # Audio profiles: (filename, frequency_hz, duration_seconds, description)
    AUDIO_FILES = [
        ("voice_sample_1.wav",  440,  5, "Voice frequency (440 Hz)"),
        ("music_sample_1.wav",  880,  5, "Music frequency (880 Hz)"),
        ("ambient_sample_1.wav", 220, 5, "Ambient frequency (220 Hz)"),
    ]

    # Generate clean WAV files (sine wave)
    SAMPLE_RATE = 44100
    for wav_name, freq, duration, desc in AUDIO_FILES:
        out_wav = os.path.join(AUDIO_CLEAN_DIR, wav_name)
        if not os.path.exists(out_wav):
            n_samples = SAMPLE_RATE * duration
            with wave.open(out_wav, "w") as wf:
                wf.setnchannels(1)       # mono
                wf.setsampwidth(2)       # 16-bit
                wf.setframerate(SAMPLE_RATE)
                frames = bytearray()
                for i in range(n_samples):
                    sample = int(32767 * math.sin(2 * math.pi * freq * i / SAMPLE_RATE))
                    frames += struct.pack("<h", sample)
                wf.writeframes(bytes(frames))

    # Embed using Steghide (supports WAV natively)
    wav_ok = 0
    for idx, (wav_name, _, _, _) in enumerate(AUDIO_FILES):
        # Alternate passwords: even index → stego123, odd → stegopass123
        pwd    = PASSWORD1 if idx % 2 == 0 else PASSWORD2
        cover  = os.path.join(AUDIO_CLEAN_DIR, wav_name)
        output = os.path.join(AUDIO_STEGO_DIR, f"stego_{wav_name}")
        cmd = [STEGHIDE_EXE, "embed", "-cf", cover, "-ef", SECRET_FILE,
               "-sf", output, "-p", pwd, "-f"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [OK] {wav_name} -> stego_{wav_name}  [pwd: {pwd}]")
            wav_ok += 1
        else:
            print(f"  [FAILED] {wav_name}: {result.stderr.strip()}")

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  DATASET SUMMARY")
    print("=" * 60)
    print(f"  Clean JPEG  : {len(jpeg_files)} files  (clean_dataset/jpeg/)")
    print(f"  Clean PNG   : {len(png_files)}  files  (clean_dataset/png/)")
    print(f"  Clean WAV   : {len(AUDIO_FILES)} files  (clean_dataset/audio_wav/)")
    print(f"  Stego JPEG  : {jpeg_ok}/{len(jpeg_files)} embedded  (stego_dataset/jpeg_steghide/)")
    print(f"  Stego PNG   : {png_ok}/{len(png_files)}  embedded  (stego_dataset/png_lsb/)")
    print(f"  Stego WAV   : {wav_ok}/{len(AUDIO_FILES)} embedded  (stego_dataset/audio_steghide/)")
    print(f"  Secret file : {SECRET_FILE}")
    print("  Status      : DATASET READY")
