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
import re
import sys
import time
import zlib
import json
import argparse
import subprocess

from datetime import datetime
from pwn import remote
from datetime import datetime
from pathlib import Path

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

config = {
    "host": "0.0.0.0",
    "port": 0,
    "spacecraft_id": 0,
    "virtual_channel_id": 0,
    "apid": 0,
    "packet_count": 0,
    "tc_packet_count": 0,
    "payload": b"PAYLOAD",
    }

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

# ============================================================
# MAIN MENU
# VERSION:CORE
# ============================================================

def main_menu():
    while True:
        clear_screen()
        print("")
        print("███████╗████████╗ █████╗ ██████╗   ██╗     ██╗███╗   ██╗██╗  ██╗")
        print("██╔════╝╚══██╔══╝██╔══██╗██╔══██╗  ██║     ██║████╗  ██║██║ ██╔╝")
        print("███████╗   ██║   ███████║██████╔╝  ██║     ██║██╔██╗ ██║█████╔╝")
        print("╚════██║   ██║   ██╔══██║██╔══██╗  ██║     ██║██║╚██╗██║██╔═██╗")
        print("███████║   ██║   ██║  ██║██║  ██║  ███████╗██║██║ ╚████║██║  ██╗")
        print("╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝")
        print("\033[91m         Consultative Committee for Space Data Systems\033[0m")
        print("")
        print_header()
        print()
        print("MISSION STATUS")
        print("─" * 63)
        print(f"Spacecraft           : {config['spacecraft_id']}")
        print(f"Virtual Channel      : {config['virtual_channel_id']}")
        print(f"APID                 : {config['apid']}")
        print(f"SP Sequence Count    : {config['packet_count']}")
        print(f"TC Frame Sequence    : {config['tc_packet_count']}")
        print(f"Payload              : {payload_bytes()!r}")
        print(f"Payload HEX          : {payload_bytes().hex(' ')}")
        print(f"Destination          : {config['host']}:{config['port']}")
        print()
        print("OPERATIONS")
        print("─" * 63)
        print("[01] Edit Mission Parameters")
        print("[02] View Mission Parameters")
        print("[03] Preview CCSDS Frame")
        print("[04] Display Raw Packet")
        print("[05] Check Connection to Spacecraft")
        print("─" * 63)
        print("[06] Transmit TM Type Telecommand")
        print("[07] Transmit AD Type Telecommand")
        print("[08] Dump Spacecraft EEPROM data")
        print("[09] Pass Prediction System")
        print("[10] Automated Tracking System")
        print("[11] Demodulate AFSK 1200 signals")
        print("[12] Hack Groundstation")
        print("─" * 63)
        print("[0] Exit")
        print()
        choice = input("Command selection: ").strip()
        if choice == "1":
            edit_parameters()
        elif choice == "2":
            mparams()
        elif choice == "3":
            preview()
        elif choice == "4":
            raw_packet()
        elif choice == "5":
            telemcraft()
        elif choice == "6":
            tmTelecommand()
        elif choice == "7":
            adTelecommand()
        elif choice == "8":
            eeprom()
        elif choice == "9":
            predication_system()
        elif choice == "10":
            tracking_system()
        elif choice == "11":
            demodulate()
        elif choice == "12":
            breach()
        elif choice == "0":
            exitModule()
        else:
            print("\nInvalid command.")
            pause()

# ============================================================
# CCSDS SPACE PACKET GENERATION
# VERSION:CORE
# ============================================================
#        Primary header       :
#        Version Number       : 3 bits = 000
#        Packet Type          : 1 bit  = 1 (TC)
#        Secondary Header     : 1 bit  = 0
#        APID                 : 11 bits
#        Sequence Flags       : 2 bits = 11 (unsegmented)
#        Sequence Count       : 14 bits
#        Packet Data Length   : payload_length - 1
# ============================================================

def generate_space_packet(apid: int, packet_count: int, payload: bytes) -> bytes:
    if not 0 <= apid <= 0x7FF:
        raise ValueError("APID must fit in 11 bits (0-2047)")
    if not 0 <= packet_count <= 0x3FFF:
        raise ValueError("packet_count must fit in 14 bits (0-16383)")
    if not payload:
        raise ValueError("CCSDS Packet Data Field cannot be empty")
    packet_id = (1 << 12) | apid
    sequence_control = (0b11 << 14) | packet_count
    packet_data_length = len(payload) - 1
    if packet_data_length > 0xFFFF:
        raise ValueError("Payload is too large for CCSDS Packet Data Length")
    return (packet_id.to_bytes(2, "big") + sequence_control.to_bytes(2, "big") + packet_data_length.to_bytes(2, "big") + payload) 

# ============================================================
# CCSDS TC FRAME ERROR CONTROL FIELD
# VERSION:CORE
# ============================================================
#    Polynomial:
#        X^16 + X^12 + X^5 + 1
#    Polynomial value:
#        0x1021
#    Initial value:
#        0xFFFF
# ============================================================

def ccsds_fecf(data: bytes) -> int:
    crc = 0xFFFF
    polynomial = 0x1021
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ polynomial) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def generate_tc_frame(spacecraft_id: int, virtual_channel_id: int, tc_packet_count: int, payload: bytes) -> bytes:
    if not 0 <= spacecraft_id <= 0x3FF:
        raise ValueError("spacecraft_id must fit in 10 bits (0-1023)")
    if not 0 <= virtual_channel_id <= 0x3F:
        raise ValueError("virtual_channel_id must fit in 6 bits (0-63)")
    if not 0 <= tc_packet_count <= 0xFF:
        raise ValueError("tc_packet_count must fit in 8 bits (0-255)")
    if not payload:
        raise ValueError("TC Transfer Frame Data Field cannot be empty")
    total_length = 5 + len(payload) + 2
    if total_length > 1024:
        raise ValueError("TC Transfer Frame cannot exceed 1024 octets")
    frame_length = total_length - 1
    header_byte0 = ((0b00 << 6) | (0 << 5) | (0 << 4) | (0b00 << 2) | ((spacecraft_id >> 8) & 0x03))
    header_byte1 = spacecraft_id & 0xFF
    header_byte2 = (virtual_channel_id << 2) | ((frame_length >> 8) & 0x03)
    header_byte3 = frame_length & 0xFF
    header_byte4 = tc_packet_count
    header = bytes([header_byte0,header_byte1,header_byte2,header_byte3,header_byte4,])
    frame_without_fecf = header + payload
    fecf = ccsds_fecf(frame_without_fecf)
    return frame_without_fecf + fecf.to_bytes(2, "big")

# ============================================================
# DISPLAY HELPERS
# VERSION:CORE
# ============================================================

def clear_screen():
    os.system("clear")

def pause():
    input("\nPress ENTER to continue...")

def print_header(title="SPACECRAFT CONSOLE"):
    print("╔══════════════════════════════════════════════════════════════╗")
    print(f"║ {title:^60} ║")
    print("╚══════════════════════════════════════════════════════════════╝")

# ============================================================
# TRADITIONAL OFFSET/HEX/ASCII DUMP
# VERSION:CORE
# ============================================================

def hex_dump(data: bytes, width: int = 16) -> str:
    if not data:
        return "<empty>"
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = f"{hex_part:<{width * 3 - 1}}"
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)

# ============================================================
# CONVERT BYTES TO ASCII. NON-PRINTABLE BYTES = \XNN
# VERSION:CORE
# ============================================================

def printable_ascii(data: bytes) -> str:
    result = []
    for byte in data:
        if 32 <= byte <= 126:
            result.append(chr(byte))
        elif byte == 10:
            result.append("\\n")
        elif byte == 13:
            result.append("\\r")
        elif byte == 9:
            result.append("\\t")
        else:
            result.append(f"\\x{byte:02x}")
    return "".join(result)

# ============================================================
# SPACE PACKET DECODER
# VERSION:CORE
# ============================================================

def decode_space_packet(packet: bytes, title="SPACE PACKET DECODER"):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    if len(packet) < 6:
        print(f"[!] Packet too short: {len(packet)} bytes")
        return
    packet_id = int.from_bytes(packet[0:2], "big")
    sequence_control = int.from_bytes(packet[2:4], "big")
    length_field = int.from_bytes(packet[4:6], "big")
    version = (packet_id >> 13) & 0x07
    packet_type = (packet_id >> 12) & 0x01
    secondary_header = (packet_id >> 11) & 0x01
    apid = packet_id & 0x07FF
    sequence_flags = (sequence_control >> 14) & 0x03
    sequence_count = sequence_control & 0x3FFF
    expected_length = length_field + 7
    payload = packet[6:]
    print()
    print("  HEADER")
    print("  " + "-" * 56)
    print(f"  Raw packet       : {packet.hex(' ')}")
    print(f"  Version          : {version}")
    print(f"  Packet type      : {packet_type} ({'TC' if packet_type else 'TM'})")
    print(f"  Secondary header : {secondary_header}")
    print(f"  APID             : {apid}")
    print(f"  Sequence flags   : {sequence_flags:02b}")
    print(f"  Sequence count   : {sequence_count}")
    print(f"  Length field     : {length_field}")
    print(f"  Expected length  : {expected_length}")
    print(f"  Actual length    : {len(packet)}")
    if len(packet) == expected_length:
        print("[+] Space Packet length: VALID")
    else:
        print("[!] Space Packet length: MISMATCH")
    print()
    print("  PAYLOAD")
    print("  " + "-" * 56)
    print(f"  Payload length   : {len(payload)} bytes")
    print(f"  Payload HEX      : {payload.hex(' ')}")
    print(f"  Payload ASCII    : {printable_ascii(payload)}")

# ============================================================
# TRANSFER FRAME DECODER - DECODE FIVE OCTET AD FRAME HEADER
# VERSION:CORE
# ============================================================

def decode_tc_frame(frame: bytes, title="TRANSFER FRAME DECODER"):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    if len(frame) < 7:
        print(f"[!] Frame too short: {len(frame)} bytes")
        return
    header = frame[:5]
    header_byte0 = header[0]
    header_byte1 = header[1]
    header_byte2 = header[2]
    frame_length_field = header[3]
    frame_sequence = header[4]
    tfvn = (header_byte0 >> 6) & 0x03
    bypass = (header_byte0 >> 5) & 0x01
    control_command = (header_byte0 >> 4) & 0x01
    spacecraft_id = ((header_byte0 & 0x03) << 8) | header_byte1
    virtual_channel_id = (header_byte2 >> 2) & 0x3F
    expected_length = frame_length_field + 1
    actual_length = len(frame)
    fecf_received = int.from_bytes(frame[-2:], "big")
    fecf_calculated = ccsds_fecf(frame[:-2])
    print()
    print("  TRANSFER FRAME HEADER")
    print("  " + "-" * 56)
    print(f"  TFVN             : {tfvn}")
    print(f"  Bypass flag      : {bypass}")
    print(f"  Control command  : {control_command}")
    print(f"  Spacecraft ID    : {spacecraft_id}")
    print(f"  Virtual channel  : {virtual_channel_id}")
    print(f"  Frame length fld : {frame_length_field}")
    print(f"  Expected length  : {expected_length}")
    print(f"  Actual length    : {actual_length}")
    print(f"  Frame sequence   : {frame_sequence}")
    if actual_length == expected_length:
        print("[+] Frame length: VALID")
    else:
        print("[!] Frame length: MISMATCH")
    print()
    print("  FRAME ERROR CONTROL FIELD")
    print("  " + "-" * 56)
    print(f"  FECF received    : {fecf_received:04x}")
    print(f"  FECF calculated  : {fecf_calculated:04x}")
    if fecf_received == fecf_calculated:
        print("[+] FECF: VALID")
    else:
        print("[!] FECF: INVALID")
    if len(frame) <= 7:
        print()
        print("[!] No embedded Space Packet.")
        return
    space_packet = frame[5:-2]
    print()
    print("  TRANSFER FRAME DATA FIELD")
    print("  " + "-" * 56)
    print(f"  Embedded packet  : {len(space_packet)} bytes")
    print(f"  Data HEX         : {space_packet.hex(' ')}")
    decode_space_packet(space_packet, title="EMBEDDED SPACE PACKET")


# ============================================================
# INPUT HELPERS - GET A VALIDATED INTEGER
# VERSION:CORE
# ============================================================

def get_int(prompt, minimum, maximum, current=None):
    while True:
        suffix = f" [{current}]" if current is not None else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if value == "" and current is not None:
            return current
        try:
            number = int(value, 0)
        except ValueError:
            print("  ERROR: Enter a decimal number or 0x-prefixed hexadecimal value.")
            continue
        if not minimum <= number <= maximum:
            print(f"  ERROR: Value must be between {minimum} and {maximum}.")
            continue
        return number

# ============================================================
# GET A STRING
# VERSION:CORE
# ============================================================

def get_string(prompt, current=None, allow_empty=False):
    while True:
        suffix = f" [{current}]" if current is not None else ""
        value = input(f"{prompt}{suffix}: ")
        if value == "" and current is not None:
            return current
        if not value and not allow_empty:
            print("  ERROR: Value cannot be empty.")
            continue
        return value

# ============================================================
# PAYLOAD INPUT
# VERSION:CORE
# ============================================================

def get_payload():
    print()
    print("PAYLOAD INPUT")
    print("─" * 60)
    print("[1] ASCII / TEXT")
    print("[2] HEX BYTES")
    print()
    while True:
        mode = input("Payload input mode [1/2]: ").strip()
        if mode == "1":
            value = input("ASCII payload: ")
            if not value:
                print("  ERROR: Payload cannot be empty.")
                continue
            return value.encode("utf-8")
        elif mode == "2":
            value = input("HEX payload: ").strip()
            if not value:
                print("  ERROR: Payload cannot be empty.")
                continue
            # Remove common separators.
            cleaned = (
                value.replace(" ", "")
                .replace(":", "")
                .replace("-", "")
                .replace("_", "")
            )
            if len(cleaned) % 2 != 0:
                print("  ERROR: HEX input must contain complete byte pairs.")
                continue
            try:
                payload = bytes.fromhex(cleaned)
            except ValueError:
                print("  ERROR: Invalid hexadecimal payload.")
                continue
            if not payload:
                print("  ERROR: Payload cannot be empty.")
                continue
            print()
            print("[+] Payload accepted.")
            print(f"    Length : {len(payload)} bytes")
            print(f"    HEX    : {payload.hex(' ')}")
            print(f"    ASCII  : {printable_ascii(payload)}")
            return payload
        else:
            print("  ERROR: Select 1 or 2.")

# ============================================================
# RETURN THE CONFIGURED PAYLOAD EXACTLY AS BYTES
# VERSION:CORE
# ============================================================

def payload_bytes():
    if isinstance(config["payload"], bytes):
        return config["payload"]
    return str(config["payload"]).encode("utf-8")

# ============================================================
# BUILD SPACE PACKET AND TC FRAME.
# VERSION:CORE
# ============================================================

def build_packets():
    space_packet = generate_space_packet(apid=config["apid"],packet_count=config["packet_count"],payload=payload_bytes(),)
    frame = generate_tc_frame(spacecraft_id=config["spacecraft_id"],virtual_channel_id=config["virtual_channel_id"],tc_packet_count=config["tc_packet_count"],payload=space_packet,)
    return space_packet, frame

# ============================================================
# CONFIGURATION
# VERSION:CORE
# ============================================================

def show_configuration():
    clear_screen()
    print_header("MISSION PARAMETERS")
    print()
    print(f"  [1] Target Host            : {config['host']}")
    print(f"  [2] Target Port            : {config['port']}")
    print()
    print(f"  [3] Spacecraft ID          : {config['spacecraft_id']}")
    print(f"  [4] Virtual Channel ID     : {config['virtual_channel_id']}")
    print()
    print(f"  [5] APID                   : {config['apid']}")
    print(f"  [6] Space Packet Count     : {config['packet_count']}")
    print(f"  [7] TC Frame Sequence      : {config['tc_packet_count']}")
    print()
    print(f"  [8] Payload                : {payload_bytes()!r}")
    print(f"  [8H] Payload HEX           : {payload_bytes().hex(' ')}")
    print()

def edit_parameters():
    while True:
        show_configuration()
        print("  [9] Return to Main Menu")
        print()
        choice = input("  Select parameter to edit: ").strip()
        if choice == "1":
            config["host"] = get_string("Target host", config["host"])
        elif choice == "2":
            config["port"] = get_int("Target TCP port", 1, 65535, config["port"])
        elif choice == "3":
            config["spacecraft_id"] = get_int("Spacecraft ID", 0, 1023, config["spacecraft_id"])
        elif choice == "4":
            config["virtual_channel_id"] = get_int("Virtual Channel ID", 0, 63, config["virtual_channel_id"])
        elif choice == "5":
            config["apid"] = get_int("APID", 0, 2047, config["apid"])
        elif choice == "6":
            config["packet_count"] = get_int("Space Packet Sequence Count", 0, 16383, config["packet_count"])
        elif choice == "7":
            config["tc_packet_count"] = get_int("TC Frame Sequence Number", 0, 255, config["tc_packet_count"])
        elif choice == "8":
            config["payload"] = get_payload()
        elif choice == "9":
            return
        else:
            print("\n  Invalid selection.")
            pause()

# ============================================================
# MISSION PARAMETERS
# VERSION:CORE
# ============================================================

def mparams():
    clear_screen()
    print_header("MISSION PARAMETERS")
    print()
    print(f"  Target Host          : {config['host']}")
    print(f"  Target Port          : {config['port']}")
    print(f"  Spacecraft ID        : {config['spacecraft_id']}")
    print(f"  Virtual Channel ID   : {config['virtual_channel_id']}")
    print(f"  APID                 : {config['apid']}")
    print(f"  Packet Count         : {config['packet_count']}")
    print(f"  TC Frame Count       : {config['tc_packet_count']}")
    print(f"  Payload              : {payload_bytes()!r}")
    print(f"  Payload HEX          : {payload_bytes().hex(' ')}")
    print()
    pause()

# ============================================================
# PACKET PREVIEW
# VERSION:CORE
# ============================================================

def preview():
    clear_screen()
    print_header("PACKET PREVIEW")
    print()
    try:
        space_packet, frame = build_packets()
    except ValueError as exc:
        print(f"  ERROR: {exc}")
        pause()
        return
    print("GENERATED SPACE PACKET")
    print("-" * 60)
    print(f"Length : {len(space_packet)} bytes")
    print(f"HEX    : {space_packet.hex(' ')}")
    print()
    print("GENERATED TC FRAME")
    print("-" * 60)
    print(f"Length : {len(frame)} bytes")
    print(f"HEX    : {frame.hex(' ')}")
    decode_tc_frame(frame, title="TX TRANSFER FRAME DECODER")
    pause()

# ============================================================
# TRANSMISSION
# VERSION:CORE
# ============================================================

def tmTelecommand():
    clear_screen()
    print_header("TRANSMIT TM TELECOMMAND")
    config_to_send = config.copy()
    if isinstance(config_to_send["payload"], bytes):
        config_to_send["payload"] = config_to_send["payload"].decode("utf-8")
    subprocess.run([sys.executable,"tmTelecommand.py",json.dumps(config_to_send),],check=True,)
    pause()

def adTelecommand():
    clear_screen()
    print_header("TRANSMIT AD TELECOMMAND")
    config_to_send = config.copy()
    if isinstance(config_to_send["payload"], bytes):
        config_to_send["payload"] = config_to_send["payload"].decode("utf-8")
    subprocess.run([sys.executable,"adTelecommand.py",json.dumps(config_to_send),],check=True,)
    pause()

# ============================================================
# RAW PACKET
# VERSION:CORE
# ============================================================

def raw_packet():
    clear_screen()
    print_header("RAW PACKET PREVIEW")
    print()
    try:
        space_packet, frame = build_packets()
        print("SPACE PACKET")
        print("─" * 60)
        print(space_packet.hex(" "))
        print()
        print("TC FRAME")
        print("─" * 60)
        print(frame.hex(" "))
        print()
        print("FULL HEX DUMP")
        print("─" * 60)
        print(hex_dump(frame))
    except ValueError as exc:
        print(f"\n  ERROR: {exc}")
    pause()

# ============================================================
# EEPROM DUMP
# VERSION:CORE
# ============================================================
# U-Boot I2C EEPROM deep read-only reconnaissance.
# Read-only commands only:
#    version
#    printenv
#    i2c bus
#    i2c probe
#    i2c dev
#    i2c md
#
# Priority:
#    - EEPROM 0x50 on buses 0 and 1
#    - live env_offset (0x800)
#    - offsets beyond the previously dumped 0x3ff
#    - printable strings / flag-like strings
#    - possible U-Boot environment CRC
# ============================================================

def parse_args():
    DEFAULT_HOST = config["host"]
    DEFAULT_PORT = config["port"]
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    return host, port

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

def eeprom():
    io = None
    clear_screen()
    print_header("EEPROM DUMP")
    host, port = parse_args()
    outdir = (Path.home() / "Documents" / "HTB" / "SATELLITE EXPLOITATION")
    outdir.mkdir(parents=True, exist_ok=True)
    transcript_path = (outdir / f"uboot_deep_dump_{datetime.now():%Y%m%d_%H%M%S}.txt")
    print("=" * 72)
    print("U-BOOT I2C EEPROM DEEP READ-ONLY RECON")
    print("=" * 72)
    print(f"Target : {host}:{port}")
    print(f"Output : {transcript_path}")
    print()
    print("Highest-priority reads:")
    print("  Bus 1 / 0x50 / 0x0800")
    print("  Bus 0 / 0x50 / 0x0800")
    print()
    print("No setenv/saveenv/mw/write/boot/reset commands are used.")
    transcript = []
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
    pause()

# ============================================================
# CONNECT
# VERSION:CORE
# ============================================================

def telemcraft():
    clear_screen()
    print_header("TELNET TO SPACECRAFT")
    TEL_HOST = config["host"]
    TEL_PORT = config["port"]
    import subprocess
    subprocess.run(["telnet", TEL_HOST, str(TEL_PORT)]) 
    pause()

# ============================================================
# Pass Predication System
# VERSION:CORE
# ============================================================

def predication_system():
    clear_screen()
    print_header("PASS PREDICATION SYSTEM")
    config_to_send = config.copy()
    if isinstance(config_to_send["payload"], bytes):
        config_to_send["payload"] = config_to_send["payload"].decode("utf-8")
    subprocess.run([sys.executable,"firstContact.py",json.dumps(config_to_send),],check=True,)
    pause()

# ============================================================
# Pass Tracking System
# VERSION:CORE
# ============================================================

def tracking_system():
    clear_screen()
    print_header("AUTOMATED TRACKING SYSTEM")
    config_to_send = config.copy()
    if isinstance(config_to_send["payload"], bytes):
        config_to_send["payload"] = config_to_send["payload"].decode("utf-8")
    subprocess.run([sys.executable,"antennaPointing.py",json.dumps(config_to_send),],check=True,)
    pause()

# ============================================================
# AFSK1200 DEMODULATOR
# VERSION:CORE
# ============================================================

def demodulate():
    clear_screen()
    print_header("AUTOMATED AFSK1200 Decoder")
    subprocess.run([sys.executable, "deModulator.py"], check=False)
    pause()

def exitModule():
    print()
    print_header("CONSOLE SHUTDOWN")
    print()
    print("Mission console terminated.")
    print()
    exit(1)

def breach():    
    clear_screen()
    print_header("WARNING!! - BREACHING GROUNDSTATION")
    subprocess.run([sys.executable, "groundStationBreach.py"], check=False)
    pause() 

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nConsole interrupted. Exiting.")