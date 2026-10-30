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

import argparse
import time
import json
import sys
import io
import re

from pwn import remote
from pathlib import Path
from datetime import datetime

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
    parser.add_argument("--port2", type=int, required=False)
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

host = (config["host"])
port = (config["port"])
port2 = (config["port2"])
spacecraft_id = (config["spacecraft_id"])
virtual_channel_id = (config["virtual_channel_id"])
apid = (config["apid"])
payload = (config["payload"]) # .encode("utf-8"))
packet_count = (config["packet_count"])
tc_packet_count = (config["tc_packet_count"])

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

io = None
transcript = []
outdir = Path.cwd()
outdir.mkdir(parents=True, exist_ok=True)
transcript_path = (outdir / f"uboot_deep_dump_{datetime.now():%Y%m%d_%H%M%S}.txt")

EEPROM_OFFSETS = (
    0x0000,
    0x0400,
    0x0800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    )

ENV_NAMES = {
    b"arch", b"baudrate", b"board", b"board_name",
    b"bootcmd", b"bootdelay", b"boot_targets", b"cpu",
    b"fdt_addr", b"fdtcontroladdr", b"kernel_addr_r",
    b"loadaddr", b"pxefile_addr_r", b"ramdisk_addr_r",
    b"scriptaddr", b"env_offset", b"vendor",
    }

FLAG_PATTERNS = (
    re.compile(rb"flag\{[^}\r\n]{1,256}\}", re.I),
    re.compile(rb"htb\{[^}\r\n]{1,256}\}", re.I),
    re.compile(rb"ctf\{[^}\r\n]{1,256}\}", re.I),
    )

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def send_cmd(io, cmd, delay=0.35):
    io.sendline(cmd.encode())
    time.sleep(delay)
    return io.recvrepeat(0.35).decode("latin-1", errors="replace")

# Extract U-Boot i2c md bytes and print hex + ASCII

def parse_hex_dump(text):
    data = bytearray()
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{4,8})\s+"r"((?:[0-9a-fA-F]{2}\s+){1,16})",line,)
        if not m:
            continue
        address = int(m.group(1), 16)
        hex_bytes = m.group(2).split()
        chunk = bytes(int(token, 16) for token in hex_bytes)
        data.extend(chunk)
        ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{address:08x}: "f"{' '.join(f'{b:02x}' for b in chunk):<47} " f"|{ascii_text}|")
    return bytes(data)

def analyse(bus, chip, offset, text):
    data = parse_hex_dump(text)
    print(f"\n{'=' * 72}")
    print(f"ANALYSIS  bus={bus}  device=0x{chip:02x} "f"offset=0x{offset:04x}")
    print(f"{'=' * 72}")
    if not data:
        print("[!] No bytes parsed.")
        return
    if all(b == 0x00 for b in data):
        print("[+] Entire block is 0x00.")
    elif all(b == 0xff for b in data):
        print("[+] Entire block is 0xff (likely erased/unprogrammed).")
    else:
        print(f"[+] Parsed {len(data)} bytes.")
    # Printable strings.
    strings = []
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        strings.append((offset + m.start(), m.group().decode("ascii", "replace")))
    if strings:
        print("\n[ASCII STRINGS]")
        for addr, value in strings:
            print(f"  0x{addr:04x}: {value}")
    # NUL-separated strings.
    nul_strings = []
    for part in data.split(b"\x00"):
        if len(part) >= 4 and all(32 <= b <= 126 for b in part):
            nul_strings.append(part.decode("ascii", "replace"))
    if nul_strings:
        print("\n[NUL-SEPARATED STRINGS]")
        for value in nul_strings:
            print(f"  {value}")
    # Possible U-Boot environment variables.
    env_hits = []
    for part in data.split(b"\x00"):
        if b"=" not in part:
            continue
        name, value = part.split(b"=", 1)
        if name in ENV_NAMES:
            env_hits.append(
                (
                    name.decode("ascii", "replace"),
                    value.decode("latin-1", "replace"),
                )
            )
    if env_hits:
        print("\n[POSSIBLE U-BOOT ENVIRONMENT]")
        for name, value in env_hits:
            print(f"  {name}={value}")
    # Flag hunting.
    flag_hits = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.finditer(data):
            flag_hits.append(
                (offset + match.start(),match.group().decode("latin-1", "replace"),))
    if flag_hits:
        print("\n" + "!" * 72)
        print("[!!!] POSSIBLE FLAG FOUND")
        for addr, flag in flag_hits:
            print(f"  0x{addr:04x}: {flag}")
        print("!" * 72)
    # Useful challenge keywords.
    keywords = (b"flag", b"secret", b"password", b"token", b"payload", b"mission", b"satellite", b"spacecraft", b"recovery", b"aes", b"key", b"iv",)
    lower = data.lower()
    keyword_hits = []
    for keyword in keywords:
        start = 0
        while True:
            pos = lower.find(keyword, start)
            if pos < 0:
                break
            keyword_hits.append((offset + pos, keyword.decode("ascii")))
            start = pos + len(keyword)
    if keyword_hits:
        print("\n[INTERESTING KEYWORDS]")
        for addr, keyword in keyword_hits:
            print(f"  0x{addr:04x}: {keyword}")
    # CRC32 heuristic.
    # For a legacy U-Boot environment, the first four bytes can be
    # a CRC over the following environment data.
    if len(data) >= 8:
        stored_be = int.from_bytes(data[:4], "big")
        stored_le = int.from_bytes(data[:4], "little")
        calculated = zlib.crc32(data[4:]) & 0xffffffff
        print("\n[CRC32 CHECK]")
        print(f"  first four bytes : {data[:4].hex()}")
        print(f"  stored BE        : 0x{stored_be:08x}")
        print(f"  stored LE        : 0x{stored_le:08x}")
        print(f"  calculated       : 0x{calculated:08x}")
        if calculated in (stored_be, stored_le):
            print("  [!!!] DIRECT CRC32 MATCH - investigate this block as environment data.")
    # Compact raw preview for useful blocks.
    if not all(b == 0 for b in data) and not all(b == 0xff for b in data):
        print("\n[RAW PREVIEW - FIRST 128 BYTES]")
        for i in range(0, min(128, len(data)), 16):
            chunk = data[i:i + 16]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"  {offset + i:08x}  " f"{hx:<47}  |{asc}|")

def print_header(title):
    print("╔" + "═" * 98 + "╗")
    print(f"║ {title:^96} ║")
    print("╚" + "═" * 98 + "╝\n")

def eeprom_dump():
    print_header("EEPROM DUMPER")
    try:
        io = remote(host, port)
        initial = io.recvrepeat(1.5).decode("latin-1", errors="replace")
        print(initial, end="")
        transcript.append(initial)
        for cmd in ("version", "i2c bus", "i2c probe", "printenv"):	# Basic read-only information.
            print(f"\n>>> {cmd}")
            output = send_cmd(io, cmd)
            print(output, end="")
            transcript.append(f"\n>>> {cmd}\n{output}")
        for bus in (0, 1):						# Recon each bus.
            print("\n" + "#" * 72)
            print(f"# I2C BUS {bus}")
            print("#" * 72)
            cmd = f"i2c dev {bus}"
            print(f"\n>>> {cmd}")
            output = send_cmd(io, cmd)
            print(output, end="")
            transcript.append(f"\n>>> {cmd}\n{output}")
            for offset in EEPROM_OFFSETS:				# EEPROM 0x50 - this is the main target.
                cmd = f"i2c md 50 {offset:x} {0x0400:x}"
                print(f"\n>>> {cmd}")
                output = send_cmd(io, cmd, delay=0.5)
                print(output, end="")
                transcript.append(f"\n>>> {cmd}\n{output}")
                analyse(bus, 0x50, offset, output)
            for chip in (0x18, 0x68):					 # Small reads of the other responding devices.
                cmd = f"i2c md {chip:x} 0 40"
                print(f"\n>>> {cmd}")
                output = send_cmd(io, cmd)
                print(output, end="")
                transcript.append(f"\n>>> {cmd}\n{output}")
                analyse(bus, chip, 0, output)
        cmd = "printenv env_offset"		        		# Confirm the live offset one final time.
        print(f"\n>>> {cmd}")
        output = send_cmd(io, cmd)
        print(output, end="")
        transcript.append(f"\n>>> {cmd}\n{output}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as exc:
        print(f"\n[!] Error: {exc}")
    finally:
        if io:
            try:
                io.close()
            except Exception:
                pass
        transcript_path.write_text("".join(transcript),encoding="latin-1",errors="replace",)
        print("\n" + "=" * 72)
        print("DONE")
        print("=" * 72)
        print(f"Transcript: {transcript_path}")
        print()
        print("Check the 0x0800 sections first.")
        print("If 0x0800 is interesting, paste that section for parsing.")

if __name__ == "__main__":
    eeprom_dump()