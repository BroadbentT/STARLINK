#!/usr/bin/env python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#           PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF SPACE CRAFT
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import wave
import subprocess
import numpy as np
from scipy import signal

from pwn import hexdump, log, remote

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def demodulate():
    wav_files = [f for f in os.listdir(".") if f.lower().endswith(".wav") and os.path.isfile(f) ]
    if wav_files:
        print("WAV files in the current directory:")
        for f in wav_files:
            print(f" - {f}")
    else:
        print("No WAV files found in the current directory.")
        pause()
        return
    while True:
        path = input("\nEnter the WAV filename: ").strip()
        if not path.lower().endswith(".wav"):
            print("Please enter a filename ending in .wav.")
        elif os.path.isfile(path):
            print(f"File found: {path}")
            break
        else:
            print("File not found. Please try again.")


    # STAGE 1: LOAD WAV FILE

    print("\n" + "=" * 60)
    print("[1] LOADING WAV FILE")
    print("=" * 60)
    try:
        with wave.open(path, "rb") as wf:
            sr = wf.getframerate()
            nch = wf.getnchannels()
            sample_width = wf.getsampwidth()
            nframes = wf.getnframes()
            duration = nframes / sr
            raw = wf.readframes(nframes)
    except (wave.Error, OSError) as exc:
        print(f"ERROR: Unable to read WAV file: {exc}")
        pause()
        return

    print(f"    Filename           : {path}")
    print(f"    Sample rate        : {sr} Hz")
    print(f"    Channels           : {nch}")
    print(f"    Sample width       : {sample_width * 8} bits")
    print(f"    Total frames       : {nframes}")
    print(f"    Duration           : {duration:.2f} seconds")
    print(f"    Raw data size      : {len(raw)} bytes")

    if sample_width != 2:
        print("\nWARNING: This decoder currently expects 16-bit PCM audio.")
        pause()
        return

    if sr < 1200:
        print("\nERROR: Sample rate is too low for 1200 baud.")
        pause()
        return

    if nframes == 0:
        print("\nERROR: The WAV file contains no audio frames.")
        pause()
        return

    if nch not in (1, 2):
        print(f"\nERROR: Unsupported channel count: {nch}")
        pause()
        return

    # STAGE 2: PREPARE AUDIO SAMPLES

    print("\n" + "=" * 60)
    print("[2] PREPARING AUDIO SAMPLES")
    print("=" * 60)
    audio = np.frombuffer(raw, dtype=np.int16).astype(np.float32)
    print(f"    Initial sample count: {len(audio)}")
    if nch == 2:
        print("    Stereo detected; converting to mono...")
        audio = audio.reshape(-1, 2).mean(axis=1)
    audio = audio / 32768.0

    print(f"    Mono sample count  : {len(audio)}")
    print(f"    Minimum amplitude  : {np.min(audio):.4f}")
    print(f"    Maximum amplitude  : {np.max(audio):.4f}")
    print(f"    Mean amplitude     : {np.mean(audio):.4f}")
    print(f"    RMS amplitude      : {np.sqrt(np.mean(audio**2)):.4f}")

    # STAGE 3: CALCULATE INSTANTANEOUS FREQUENCY

    print("\n" + "=" * 60)
    print("[3] CALCULATING INSTANTANEOUS FREQUENCY")
    print("=" * 60)
    analytic = signal.hilbert(audio)
    phase = np.unwrap(np.angle(analytic))
    inst_freq = np.diff(phase) * sr / (2 * np.pi)
    print(f"    Analytic samples   : {len(analytic)}")
    print(f"    Frequency samples  : {len(inst_freq)}")
    if len(inst_freq) == 0:
        print("ERROR: No frequency samples available.")
        pause()
        return
    print(f"    Minimum frequency : {np.min(inst_freq):.2f} Hz")
    print(f"    Maximum frequency : {np.max(inst_freq):.2f} Hz")
    print(f"    Mean frequency    : {np.mean(inst_freq):.2f} Hz")

    # STAGE 4: EXTRACT AFSK1200 SYMBOLS

    print("\n" + "=" * 60)
    print("[4] EXTRACTING AFSK1200 SYMBOLS")
    print("=" * 60)
    bps = sr // 1200
    if bps < 1:
        print("ERROR: Invalid samples-per-bit value.")
        pause()
        return
    nb = len(inst_freq) // bps
    if nb == 0:
        print("ERROR: Audio is too short to decode.")
        pause()
        return
    print(f"    Target baud rate   : 1200")
    print(f"    Samples per bit    : {bps}")
    print(f"    Estimated bit count: {nb}")
    freq_per_bit = (inst_freq[:nb * bps].reshape(nb, bps).mean(axis=1))
    print("\n    First 20 symbol frequency estimates:")
    for i, freq in enumerate(freq_per_bit[:20]):
        print(f"        Symbol {i:04d}: {freq:10.2f} Hz")
    if len(freq_per_bit) > 20:
        print(f"        ... {len(freq_per_bit) - 20} more symbols")

    # STAGE 5: CLASSIFY FREQUENCIES INTO TONES

    print("\n" + "=" * 60)
    print("[5] CLASSIFYING FREQUENCIES INTO TONES")
    print("=" * 60)
    threshold = 1700
    print(f"    Frequency threshold: {threshold} Hz")
    print("    Above threshold    : Tone 1")
    print("    At/below threshold : Tone 0")
    tone = (freq_per_bit > threshold).astype(int)
    tone_1_count = int(np.sum(tone == 1))
    tone_0_count = int(np.sum(tone == 0))
    print(f"\n    Tone 1 count       : {tone_1_count}")
    print(f"    Tone 0 count       : {tone_0_count}")
    print(f"    Total tones        : {len(tone)}")
    print("\n    First 64 classified tones:")
    print("    " + "".join(map(str, tone[:64])))

    # STAGE 6: CONVERT TONES TO DATA BITS

    print("\n" + "=" * 60)
    print("[6] CONVERTING TONES TO DATA BITS")
    print("=" * 60)
    data_bits = 1 - tone
    print(f"    Total data bits    : {len(data_bits)}")
    print("    First 64 data bits :")
    print("    " + "".join(map(str, data_bits[:64])))

    # STAGE 7: RECONSTRUCT BYTES

    print("\n" + "=" * 60)
    print("[7] RECONSTRUCTING BYTES")
    print("=" * 60)
    out = ""
    byte_count = len(data_bits) // 8
    remaining_bits = len(data_bits) % 8
    print(f"    Complete bytes     : {byte_count}")
    print(f"    Remaining bits     : {remaining_bits}")
    for i in range(0, len(data_bits), 8):
        byte = data_bits[i:i + 8]
        if len(byte) == 8:
            val = sum(int(b) << (7 - j) for j, b in enumerate(byte))
            char = chr(val)
            out += char
            print(
                f"    Byte {i // 8:04d}: "
                f"bits={''.join(map(str, byte))} "
                f"value={val:3d} "
                f"hex=0x{val:02X} "
                f"char={repr(char)}"
            )

    # STAGE 8: FINAL DECODE SUMMARY

    print("\n" + "=" * 60)
    print("[8] DEMODULATION SUMMARY")
    print("=" * 60)
    print(f"    Input file          : {path}")
    print(f"    Audio duration      : {duration:.2f} seconds")
    print(f"    Sample rate         : {sr} Hz")
    print(f"    Baud rate           : 1200")
    print(f"    Symbols processed   : {nb}")
    print(f"    Bits processed      : {len(data_bits)}")
    print(f"    Bytes reconstructed : {len(out)} characters")
    print("\n" + "=" * 60)
    print("DECODED OUTPUT")
    print("=" * 60)
    print(out)

# ============================================================
# MAIN ENTRY POINT
# ============================================================

if __name__ == "__main__":
    demodulate()
