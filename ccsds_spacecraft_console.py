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
import math
import socket
import argparse
import telnetlib

from skyfield.api import EarthSatellite, load, wgs84
from datetime import datetime, timezone, timedelta
from sgp4.api import Satrec, jday
from pwn import remote, context
from datetime import datetime
from pathlib import Path

context.log_level = "error"

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

ELEVATION_THRESHOLD = 30.0
SEARCH_SECONDS = 24 * 60 * 60
STEP_SECONDS = 10
CHUNK_SIZE = 0x0400
DEVICES = (0x18, 0x50, 0x68)
VISIBILITY = 30.0
SEARCH_HOURS = 48

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
        print("[1] Edit Mission Parameters")
        print("[2] View Mission Parameters")
        print("[3] Preview CCSDS Frame")
        print("[4] Display Raw Packet")
        print("[5] Transmit TM Type Telecommand")
        print("[6] Transmit AD Type Telecommand")
        print("[7] Telnet to Spacecraft") 
        print("[8] Dump Spacecraft EEPROM data")
        print("[9] Pass Prediction System")
        print("[10] Automated Tracking System")
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
            transmit()
        elif choice == "6":
            print("\n[!] AD Type Telecommand handler not implemented yet.")
            pause()
        elif choice == "7":
            telemcraft()
        elif choice == "8":
            eeprom()
        elif choice == "9":
            predication_system()
        elif choice == "10":
            tracking_system()
        elif choice == "0":
            print()
            print_header("CONSOLE SHUTDOWN")
            print()
            print("Mission console terminated.")
            print()
            break
        else:
            print("\nInvalid command.")
            pause()

# ============================================================
# CCSDS SPACE PACKET GENERATION
# ============================================================
"""
    Generate a CCSDS Space Packet.

    Primary header:
        Version Number       : 3 bits = 000
        Packet Type          : 1 bit  = 1 (TC)
        Secondary Header     : 1 bit  = 0
        APID                 : 11 bits
        Sequence Flags       : 2 bits = 11 (unsegmented)
        Sequence Count       : 14 bits
        Packet Data Length   : payload_length - 1
"""
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
# CCSDS FECF / CRC
# ============================================================
"""
    Calculate the CCSDS TC Frame Error Control Field.

    Polynomial:
        X^16 + X^12 + X^5 + 1
    Polynomial value:
        0x1021
    Initial value:
        0xFFFF
"""
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

# ============================================================
"""
Verify the final two octets as the FECF.
"""
# ============================================================

def verify_fecf(frame: bytes) -> bool:
    if len(frame) < 2:
        return False
    received = int.from_bytes(frame[-2:], "big")
    calculated = ccsds_fecf(frame[:-2])
    return received == calculated

# ============================================================
# TC TRANSFER FRAME GENERATION
# ============================================================
"""
    Generate the observed AD TC Transfer Frame.

    Five-octet primary header:
        Byte 0:
            TFVN / Bypass / Control / SCID upper bits
        Byte 1:
            SCID lower 8 bits
        Byte 2:
            VCID / Frame Length upper bits
        Byte 3:
            Frame Length lower 8 bits
        Byte 4:
            Frame Sequence Number
    FECF:
        Final two octets.
"""
# ============================================================

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
    header = bytes(
        [
            header_byte0,
            header_byte1,
            header_byte2,
            header_byte3,
            header_byte4,
        ]
    )
    frame_without_fecf = header + payload
    fecf = ccsds_fecf(frame_without_fecf)
    return frame_without_fecf + fecf.to_bytes(2, "big")

# ============================================================
# DISPLAY HELPERS
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
# Traditional offset / HEX / ASCII dump.
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
# Convert bytes into a readable representation.
# Non-printable bytes are shown as \\xNN.
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
# Determine whether a response looks like ASCII text.
# ============================================================

def is_mostly_printable(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    return (printable / len(data)) >= 0.85

# ============================================================
# SPACE PACKET DECODER
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
# TRANSFER FRAME DECODER - Decode the observed five-octet AD frame header.
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
# RESPONSE ANALYSIS - Detailed analysis of received data.
# ============================================================

def analyze_response(response: bytes):
    print()
    print("=" * 60)
    print("RX ANALYSIS")
    print("=" * 60)
    print(f"Received bytes : {len(response)}")
    if not response:
        print("[!] Empty response.")
        return
    print()
    print("HEX DUMP")
    print("-" * 60)
    print(hex_dump(response))
    print()
    print("RAW HEX")
    print("-" * 60)
    print(response.hex(" "))
    print()
    print("ASCII REPRESENTATION")
    print("-" * 60)
    print(printable_ascii(response))
    if is_mostly_printable(response):
        print()
        print("[+] Protocol detection: TEXT / ASCII")
        print("-" * 60)
        try:
            text = response.decode("utf-8", errors="replace")
            print(text, end="" if text.endswith("\n") else "\n")
        except Exception:
            pass
        markers = [
            b"SCID=",
            b"VCID=",
            b"APID=",
            b"Awaiting",
            b"APPLICATION:",
            b"ACK",
            b"FLAG",
            b"GETFLAG",
            b"ERROR",
            b"invalid",
            b"sequence",
            b"counter",
        ]
        print()
        print("DETECTED MARKERS")
        print("-" * 60)
        found = False
        response_lower = response.lower()
        for marker in markers:
            if marker.lower() in response_lower:
                print(f"[+] Detected marker: {marker.decode(errors='replace')}")
                found = True
        if not found:
            print("[*] No known application markers detected.")
        return
    print()
    print("[+] Protocol detection: BINARY")
    if len(response) >= 7:
        tfvn = (response[0] >> 6) & 0x03
        print()
        print(f"[*] Candidate TFVN: {tfvn}")
        if tfvn == 0:
            print("[*] Attempting FECF validation...")
            if verify_fecf(response):
                print("[+] FECF: VALID")
                frame_length_field = response[3]
                expected_length = frame_length_field + 1
                print()
                print(f"Frame length field : {frame_length_field}")
                print(f"Expected length    : {expected_length}")
                print(f"Actual length      : {len(response)}")
                if expected_length == len(response):
                    print("[+] Frame length: VALID")
                else:
                    print("[!] Frame length: MISMATCH")
                space_packet = response[5:-2]
                print()
                print(f"Embedded packet    : {len(space_packet)} bytes")
                decode_space_packet(space_packet, title="EMBEDDED RX SPACE PACKET")
                return
            else:
                print("[!] FECF validation failed.")
    print()
    print("[!] Binary response could not be confidently decoded as a CCSDS frame.")

# ============================================================
# TCP RECEIVE - Receive data in chunks.TCP is a byte stream, so individual recv(). 
# calls are not assumed to represent complete protocol messages.
# ============================================================

def receive_data(connection, timeout=3.0, label="RX"):
    chunks = []
    total = 0
    connection.timeout = timeout
    print()
    print(f"[*] {label}: waiting for data...")
    while True:
        try:
            chunk = connection.recv(4096)
        except Exception:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        print(f"[{label}] Received {len(chunk)} bytes (total {total})")
        print(f"[{label}] HEX: {chunk.hex(' ')}")
        print(f"[{label}] ASCII: {printable_ascii(chunk)}")
        connection.timeout = 0.35
    response = b"".join(chunks)
    print()
    print(f"[*] {label}: total received = {len(response)} bytes")
    return response

# ============================================================
# INPUT HELPERS - Get a validated integer
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
# Return the configured payload exactly as bytes.
# ============================================================

def payload_bytes():
    if isinstance(config["payload"], bytes):
        return config["payload"]
    return str(config["payload"]).encode("utf-8")

# ============================================================
# Build Space Packet and TC frame.
# ============================================================

def build_packets():
    space_packet = generate_space_packet(
        apid=config["apid"],
        packet_count=config["packet_count"],
        payload=payload_bytes(),
    )
    frame = generate_tc_frame(
        spacecraft_id=config["spacecraft_id"],
        virtual_channel_id=config["virtual_channel_id"],
        tc_packet_count=config["tc_packet_count"],
        payload=space_packet,
    )
    return space_packet, frame

# ============================================================
# CONFIGURATION
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
# ============================================================

def transmit():
    clear_screen()
    print_header("TRANSMIT TELECOMMAND")
    try:
        space_packet, frame = build_packets()
    except ValueError as exc:
        print()
        print(f"  ERROR: {exc}")
        pause()
        return
    print()
    print("TRANSMISSION PARAMETERS")
    print("─" * 60)
    print(f"Destination          : {config['host']}:{config['port']}")
    print(f"Spacecraft ID        : {config['spacecraft_id']}")
    print(f"Virtual Channel ID   : {config['virtual_channel_id']}")
    print(f"APID                 : {config['apid']}")
    print(f"SP Sequence Count    : {config['packet_count']}")
    print(f"TC Frame Sequence    : {config['tc_packet_count']}")
    print(f"Payload              : {payload_bytes()!r}")
    print(f"Payload HEX          : {payload_bytes().hex(' ')}")
    print(f"Payload ASCII        : {printable_ascii(payload_bytes())}")
    print(f"Space Packet Size    : {len(space_packet)} bytes")
    print(f"TC Frame Size        : {len(frame)} bytes")
    print()
    print("TX FRAME HEX")
    print("─" * 60)
    print(frame.hex(" "))
    print()
    print("TX FRAME DUMP")
    print("─" * 60)
    print(hex_dump(frame))
    print()
    print("WARNING: This will transmit the generated frame.")
    confirm = input("\nContinue? [y/N]: ").strip().lower()
    if confirm != "y":
        print("\nTransmission cancelled.")
        pause()
        return
    print()
    print("=" * 60)
    print("CONNECT")
    print("=" * 60)
    print(f"[*] Connecting to {config['host']}:{config['port']}...")
    try:
        r = remote(config["host"], int(config["port"]))
        print("[+] TCP connection established.")
        print()
        print("=" * 60)
        print("INITIAL SPACECRAFT RESPONSE")
        print("=" * 60)
        banner = receive_data(r, timeout=3.0, label="RX")
        if banner:
            print()
            print(f"[*] Server sent {len(banner)} initial bytes.")
            analyze_response(banner)
        else:
            print("[!] No initial server data.")
        print()
        decode_tc_frame(frame, title="TX TRANSFER FRAME DECODER")
        print()
        print("=" * 60)
        print("TRANSMITTING")
        print("=" * 60)
        print(f"TX bytes : {len(frame)}")
        print(f"TX HEX   : {frame.hex(' ')}")
        print()
        print("TX HEX DUMP")
        print("─" * 60)
        print(hex_dump(frame))
        print()
        print("[*] Sending frame...")
        sent = r.send(frame)
        print("[+] Frame transmitted.")
        print(f"[+] {len(frame)} bytes sent successfully.")
        print()
        print("=" * 60)
        print("WAITING FOR SPACECRAFT RESPONSE")
        print("=" * 60)
        response = receive_data(r, timeout=4.0, label="RX")
        if response:
            analyze_response(response)
        else:
            print()
            print("[!] No response received after telecommand.")
        print()
        print("[*] Closing connection...")
        r.close()
        print("[+] Connection closed.")
    except Exception as exc:
        print()
        print("=" * 60)
        print("TRANSMISSION ERROR")
        print("=" * 60)
        print(f"{type(exc).__name__}: {exc}")
    pause()

# ============================================================
# RAW PACKET
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
# ============================================================

"""
U-Boot I2C EEPROM deep read-only reconnaissance.

Read-only commands only:
    version
    printenv
    i2c bus
    i2c probe
    i2c dev
    i2c md

Priority:
    - EEPROM 0x50 on buses 0 and 1
    - live env_offset (0x800)
    - offsets beyond the previously dumped 0x3ff
    - printable strings / flag-like strings
    - possible U-Boot environment CRC
"""

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

def parse_hex_dump(text):

    """Extract U-Boot i2c md bytes and print hex + ASCII."""

    data = bytearray()
    for line in text.splitlines():
        m = re.match(
            r"^\s*([0-9a-fA-F]{4,8})\s+"
            r"((?:[0-9a-fA-F]{2}\s+){1,16})",
            line,
        )
        if not m:
            continue
        address = int(m.group(1), 16)
        hex_bytes = m.group(2).split()
        chunk = bytes(int(token, 16) for token in hex_bytes)
        data.extend(chunk)
        ascii_text = "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in chunk
        )
        print(
            f"{address:08x}: "
            f"{' '.join(f'{b:02x}' for b in chunk):<47} "
            f"|{ascii_text}|"
        )
    return bytes(data)

def analyse(bus, chip, offset, text):
    data = parse_hex_dump(text)
    print(f"\n{'=' * 72}")
    print(
        f"ANALYSIS  bus={bus}  device=0x{chip:02x} "
        f"offset=0x{offset:04x}"
    )
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
        strings.append(
            (offset + m.start(), m.group().decode("ascii", "replace"))
        )
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
                (
                    offset + match.start(),
                    match.group().decode("latin-1", "replace"),
                )
            )
    if flag_hits:
        print("\n" + "!" * 72)
        print("[!!!] POSSIBLE FLAG FOUND")
        for addr, flag in flag_hits:
            print(f"  0x{addr:04x}: {flag}")
        print("!" * 72)
    # Useful challenge keywords.
    keywords = (
        b"flag", b"secret", b"password", b"token",
        b"payload", b"mission", b"satellite", b"spacecraft",
        b"recovery", b"aes", b"key", b"iv",
    )
    lower = data.lower()
    keyword_hits = []
    for keyword in keywords:
        start = 0
        while True:
            pos = lower.find(keyword, start)
            if pos < 0:
                break
            keyword_hits.append(
                (offset + pos, keyword.decode("ascii"))
            )
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
            print(
                "  [!!!] DIRECT CRC32 MATCH - "
                "investigate this block as environment data."
            )
    # Compact raw preview for useful blocks.
    if not all(b == 0 for b in data) and not all(b == 0xff for b in data):
        print("\n[RAW PREVIEW - FIRST 128 BYTES]")
        for i in range(0, min(128, len(data)), 16):
            chunk = data[i:i + 16]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(
                chr(b) if 32 <= b <= 126 else "."
                for b in chunk
            )
            print(
                f"  {offset + i:08x}  "
                f"{hx:<47}  |{asc}|"
            )

def eeprom():
    io = None
    clear_screen()
    print_header("EEPROM DUMP")
    host, port = parse_args()
    outdir = (
        Path.home()
        / "Documents"
        / "HTB"
        / "SATELLITE EXPLOITATION"
    )
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
                cmd = f"i2c md 50 {offset:x} {CHUNK_SIZE:x}"
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

def telemcraft():
    clear_screen()
    print_header("TELNET TO SPACECRAFT")
    TEL_HOST = config["host"]
    TEL_PORT = config["port"]
    import subprocess
    subprocess.run(["telnet", TEL_HOST, str(TEL_PORT)]) 
    pause()

# ============================================================
# Satellite Pass Calculator
# ============================================================

def propagate(sat, dt):
    jd, fr = jday(
        dt.year, dt.month, dt.day,
        dt.hour, dt.minute,
        dt.second + dt.microsecond / 1e6,)
    error, position, _ = sat.sgp4(jd, fr)
    if error != 0:
        raise RuntimeError(f"SGP4 error {error}")
        pass
    return position

def gmst(dt):
    jd, fr = jday(
        dt.year, dt.month, dt.day,
        dt.hour, dt.minute,
        dt.second + dt.microsecond / 1e6,)
    jd_full = jd + fr
    T = (jd_full - 2451545.0) / 36525.0
    theta = (
        280.46061837
        + 360.98564736629 * (jd_full - 2451545.0)
        + 0.000387933 * T * T
        - T * T * T / 38710000.0)
    return math.radians(theta % 360.0)

def station_ecef(lat_deg, lon_deg):
    lat = math.radians(lat_deg)
    lon = math.radians(lon_deg)
    a = 6378.137
    f = 1.0 / 298.257223563
    e2 = f * (2.0 - f)
    sin_lat = math.sin(lat)
    cos_lat = math.cos(lat)
    N = a / math.sqrt(1.0 - e2 * sin_lat * sin_lat)
    return (
        N * cos_lat * math.cos(lon),
        N * cos_lat * math.sin(lon),
        N * (1.0 - e2) * sin_lat,)

def teme_to_ecef(position, dt):
    theta = gmst(dt)
    x, y, z = position
    c = math.cos(theta)
    s = math.sin(theta)
    return (
        c * x + s * y,
        -s * x + c * y,
        z,)

def elevation_deg(sat, station_lat, station_lon, dt):
    """Calculate satellite elevation above the ground station."""
    sat_ecef = teme_to_ecef(propagate(sat, dt), dt)
    sx, sy, sz = station_ecef(station_lat, station_lon)
    dx = sat_ecef[0] - sx
    dy = sat_ecef[1] - sy
    dz = sat_ecef[2] - sz
    lat = math.radians(station_lat)
    lon = math.radians(station_lon)
    sin_lat = math.sin(lat)
    cos_lat = math.cos(lat)
    sin_lon = math.sin(lon)
    cos_lon = math.cos(lon)
    east = -sin_lon * dx + cos_lon * dy
    north = (
        -sin_lat * cos_lon * dx
        - sin_lat * sin_lon * dy
        + cos_lat * dz)
    up = (
        cos_lat * cos_lon * dx
        + cos_lat * sin_lon * dy
        + sin_lat * dz)
    horizontal = math.sqrt(east * east + north * north)
    return math.degrees(math.atan2(up, horizontal))

def refine_crossing(sat, lat, lon, low, high, threshold=ELEVATION_THRESHOLD):
    low_value = elevation_deg(sat, lat, lon, low) - threshold
    high_value = elevation_deg(sat, lat, lon, high) - threshold
    for _ in range(35):
        middle = low + (high - low) / 2
        middle_value = elevation_deg(sat, lat, lon, middle) - threshold
        if (low_value <= 0 <= middle_value) or (
            low_value >= 0 >= middle_value):
            high = middle
            high_value = middle_value
        else:
            low = middle
            low_value = middle_value
    return low + (high - low) / 2

def find_passes(sat, lat, lon, start):
    """Find all complete >=30-degree visibility windows in the next 24h."""
    end = start + timedelta(seconds=SEARCH_SECONDS)
    threshold = ELEVATION_THRESHOLD
    passes = []
    previous_time = start
    previous_elevation = elevation_deg(sat, lat, lon, start) - threshold
    currently_visible = previous_elevation >= 0
    rise_time = start if currently_visible else None
    current = start + timedelta(seconds=STEP_SECONDS)
    while current <= end:
        current_elevation = elevation_deg(sat, lat, lon, current) - threshold
        if previous_elevation < 0 <= current_elevation:
            rise_time = refine_crossing(
                sat, lat, lon, previous_time, current, threshold)
        elif previous_elevation >= 0 > current_elevation:
            set_time = refine_crossing(
                sat, lat, lon, previous_time, current, threshold)
            if rise_time is not None:
                passes.append((rise_time, set_time))
            rise_time = None
        previous_time = current
        previous_elevation = current_elevation
        current += timedelta(seconds=STEP_SECONDS)
    if rise_time is not None:
        passes.append((rise_time, end))
    return passes

def format_timestamp(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def calculate_answer(tle1, tle2, lat, lon, start=None):
    sat = Satrec.twoline2rv(tle1, tle2)
    if start is None:
        start = datetime.now(timezone.utc)
    passes = find_passes(sat, lat, lon, start)
    if passes and passes[0][0] <= start:
        passes = passes[1:]
    timestamps = []
    for rise, setting in passes:
        if setting <= start + timedelta(seconds=SEARCH_SECONDS):
            timestamps.extend([format_timestamp(rise),format_timestamp(setting),])
    return " ".join(timestamps)

def predication_system():
    clear_screen()
    print_header("AUTOMATED PASS PREDICTION SYSTEM")
    print()
    tle1 = input("TLE 1 value: ");tle1 = tle1.replace('"','')
    tle2 = input("TLE 2 value: ");tle2 = tle2.replace('"','')
    if not tle1.startswith("1 "):
        tle1 = "1 " + tle1
    if not tle2.startswith("2 "):
        tle2 = "2 " + tle2
    while True:
        value = input("Ground station coordinates (latitude,longitude): ").strip().strip("\"'")
        if not value:
            print("Coordinates cannot be empty.")
            continue
        try:
            latitude, longitude = map(float, value.split(",", 1))
            break
        except ValueError:
            print("Please enter valid coordinates in the format: latitude,longitude")
    try:
       answer = calculate_answer(tle1,tle2,latitude,longitude,)
    except:
            print("\nERROR: One ofthe entered values is incorrect")           
    else:
       print("\n" + answer)
    pause()

def tracking_system():
    clear_screen()
    print_header("AUTOMATED TRACKING SYSTEM")
    print("Enter the two TLE lines and the ground-station coordinates.\n")
    tle1 = input("1. TLE1 VALUE: ").strip()
    tle2 = input("2. TLE2 VALUE: ").strip()
    while True:
        coordinates = input("3. Lat,Long: ").strip()
        match = re.fullmatch(
            r"\s*([-+]?\d+(?:\.\d+)?)\s*,\s*([-+]?\d+(?:\.\d+)?)\s*",
            coordinates,
        )
        if not match:
            print("Please enter coordinates as latitude,longitude (for example: 51.5074,-0.1278).")
            continue

        lat, lon = map(float, match.groups())
        if not -90 <= lat <= 90 or not -180 <= lon <= 180:
            print("Latitude must be between -90 and 90; longitude between -180 and 180.")
            continue
        break
    # Allow users to paste either complete TLE lines or the values without
    # their leading line numbers. Restore the standard prefixes when omitted.
    tle1 = tle1.strip()
    tle2 = tle2.strip()
    if not tle1.startswith("1 "):
        tle1 = "1 " + tle1
    if not tle2.startswith("2 "):
        tle2 = "2 " + tle2
    try:
        result = solve_challenge(tle1, tle2, lat, lon)
    except Exception as exc:
        print(f"[!] Calculation error: {exc}")
        return
    if result is None:
        print("\nANSWER: No contact window found in the next 48 hours.")
        print("If this is for a challenge that expects an empty response, use a blank answer.")
        return
    first_second, points = result
    answer = " ".join(points)
    print(f"\n[+] First contact second (UTC): {first_second.isoformat()}")
    print(f"[+] Generated {len(points)} pointing positions.")
    print("\nANSWER:")
    print(answer)
    pause()

def elevation_azimuth(satellite, station, ts, dt):
    """
    Return elevation and azimuth for a UTC datetime.
    Skyfield azimuth:
        0   = North
        90  = East
        180 = South
        270 = West
    """
    t = ts.from_datetime(dt)
    alt, az, _ = (
        satellite - station
    ).at(t).altaz()
    return alt.degrees, az.degrees % 360.0

def refine_rising(
    satellite,
    station,
    ts,
    lo,
    hi
):
    """
    Binary-search a rising crossing.
    lo = below 30 degrees
    hi = at/above 30 degrees
    """
    for _ in range(45):
        mid = lo + (hi - lo) / 2
        alt, _ = elevation_azimuth(
            satellite,
            station,
            ts,
            mid
        )
        if alt >= VISIBILITY:
            hi = mid
        else:
            lo = mid
    return hi

def refine_setting(
    satellite,
    station,
    ts,
    lo,
    hi
):
    """
    Binary-search a setting crossing.
    lo = at/above 30 degrees
    hi = below 30 degrees
    """
    for _ in range(45):
        mid = lo + (hi - lo) / 2
        alt, _ = elevation_azimuth(
            satellite,
            station,
            ts,
            mid
        )
        if alt >= VISIBILITY:
            lo = mid
        else:
            hi = mid
    return hi

def find_next_window(
    satellite,
    station,
    ts,
    start
):
    """
    Find the next visibility window where elevation >= 30 degrees.
    Returns:
        (rise, set)
    or:
        None
    Zero contact windows are supported.
    """
    end = start + timedelta(hours=SEARCH_HOURS)
    step = timedelta(seconds=5)
    previous_time = start
    previous_alt, _ = elevation_azimuth(
        satellite,
        station,
        ts,
        previous_time
    )
    current = start + step
    while current <= end:
        current_alt, _ = elevation_azimuth(
            satellite,
            station,
            ts,
            current
        )
        # ------------------------------------------------------
        # Rising through 30 degrees
        # ------------------------------------------------------
        if (
            previous_alt < VISIBILITY
            and current_alt >= VISIBILITY
        ):
            rise = refine_rising(
                satellite,
                station,
                ts,
                previous_time,
                current
            )
            # --------------------------------------------------
            # Find the corresponding setting crossing
            # --------------------------------------------------
            set_previous_time = current
            set_previous_alt = current_alt
            set_current = current + step
            while set_current <= end:
                set_alt, _ = elevation_azimuth(
                    satellite,
                    station,
                    ts,
                    set_current
                )
                if (
                    set_previous_alt >= VISIBILITY
                    and set_alt < VISIBILITY
                ):
                    set_time = refine_setting(
                        satellite,
                        station,
                        ts,
                        set_previous_time,
                        set_current
                    )
                    return rise, set_time
                set_previous_time = set_current
                set_previous_alt = set_alt
                set_current += step
            # Rise found but no set within search range.
            return rise, None
        previous_time = current
        previous_alt = current_alt
        current += step
    return None

def solve_challenge(
    tle1,
    tle2,
    lat,
    lon
):
    """
    Calculate the first 60 integer-second positions
    after the next 30-degree contact begins.
    """
    ts = load.timescale()
    satellite = EarthSatellite(
        tle1,
        tle2,
        "DIGITWIN HTB",
        ts
    )
    station = wgs84.latlon(
        latitude_degrees=lat,
        longitude_degrees=lon
    )
    now = datetime.now(timezone.utc)
    window = find_next_window(
        satellite,
        station,
        ts,
        now
    )
    # ----------------------------------------------------------
    # No contact window
    # ----------------------------------------------------------
    if window is None:
        return None
    rise, set_time = window
    # ----------------------------------------------------------
    # IMPORTANT:
    #
    # The challenge wants the first COMPLETE integer second
    # AFTER the 30-degree crossing.
    #
    # Always add one second after removing microseconds.
    #
    # Examples:
    #
    # 18:50:06.000000 -> 18:50:07
    # 18:50:06.123456 -> 18:50:07
    # 18:50:06.999999 -> 18:50:07
    #
    # This fixes the exact-integer-second edge case.
    # ----------------------------------------------------------
    first_second = (
        rise.replace(microsecond=0)
        + timedelta(seconds=1)
    )
    points = []
    for i in range(60):
        dt = (
            first_second
            + timedelta(seconds=i)
        )
        alt, az = elevation_azimuth(
            satellite,
            station,
            ts,
            dt
        )
        points.append(
            f"{alt:.4f}:{az:.4f}"
        )
    return first_second, points

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nConsole interrupted. Exiting.")