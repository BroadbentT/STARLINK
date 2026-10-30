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
import json
import sys

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
    parser.add_argument("--host", required=False)
    parser.add_argument("--port", type=int, required=False)
    parser.add_argument("--port2", type=int, required=False)
    parser.add_argument("--spacecraft-id", type=int, required=True)
    parser.add_argument("--virtual-channel-id", type=int, required=True)
    parser.add_argument("--apid", type=int, required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--packet-count", type=int, required=True)
    parser.add_argument("--tc-packet-count", type=int, required=True)
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
payload = (config["payload"].encode("utf-8"))
packet_count = (config["packet_count"])
tc_packet_count = (config["tc_packet_count"])

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

seperator = "=" * 100
underline = "-" * 100

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def print_header(title):
    print("╔" + "═" * 98 + "╗")
    print(f"║ {title:^96} ║")
    print("╚" + "═" * 98 + "╝\n")

def printable_ascii(data: bytes):
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

def payload_bytes():
    payload = config["payload"]
    return payload if isinstance(payload, bytes) else str(payload).encode("utf-8")

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

def generate_space_packet(apid: int, packet_count: int, payload: bytes):
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

def generate_tc_frame(spacecraft_id: int, virtual_channel_id: int, tc_packet_count: int, payload: bytes):
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

# ============================================================
# SPACE PACKET DECODER
# VERSION:CORE
# ============================================================

def decode_space_packet(packet: bytes, title="SPACE PACKET DECODER"):
    print("\n" + seperator)
    print(title)
    print(seperator)
    if len(packet) < 6:
        print(f"\n  [!] Packet too short: {len(packet)} bytes")
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
    print("\n  HEADER")
    print(underline)
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
        print("\n  [+] Space Packet length: VALID\n")
    else:
        print("\n  [!] Space Packet length: MISMATCH\n")
    print("  PAYLOAD")
    print(underline)
    print(f"  Payload length   : {len(payload)} bytes")
    print(f"  Payload HEX      : {payload.hex(' ')}")
    print(f"  Payload ASCII    : {printable_ascii(payload)}")

# ============================================================
# TRANSFER FRAME DECODER - DECODE FIVE OCTET AD FRAME HEADER
# VERSION:CORE
# ============================================================

def decode_tc_frame(frame: bytes, title="TRANSFER FRAME DECODER"):
    print("\n" + seperator)
    print(title)
    print(seperator + "\n")
    if len(frame) < 7:
        print(f"\n  [!] Frame too short: {len(frame)} bytes")
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
    print("  TRANSFER FRAME HEADER")
    print(underline)
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
        print("\n  [+] Frame length: VALID\n")
    else:
        print("\n  [!] Frame length: MISMATCH\n")
    print("  FRAME ERROR CONTROL FIELD")
    print(underline)
    print(f"  FECF received    : {fecf_received:04x}")
    print(f"  FECF calculated  : {fecf_calculated:04x}")
    if fecf_received == fecf_calculated:
        print("\n  [+] FECF: VALID")
    else:
        print("\n  [!] FECF: INVALID")
    if len(frame) <= 7:
        print()
        print("\n  [!] No embedded Space Packet.")
        return
    space_packet = frame[5:-2]
    print("\n  TRANSFER FRAME DATA FIELD")
    print(underline)
    print(f"  Embedded packet  : {len(space_packet)} bytes")
    print(f"  Data HEX         : {space_packet.hex(' ')}")
    decode_space_packet(space_packet, title="EMBEDDED SPACE PACKET")

def build_packets():
    space_packet = generate_space_packet(apid=int(config["apid"]),packet_count=int(config["packet_count"]),payload=payload_bytes(),)
    frame = generate_tc_frame(spacecraft_id=int(config["spacecraft_id"]),virtual_channel_id=int(config["virtual_channel_id"]),tc_packet_count=int(config["tc_packet_count"]),payload=space_packet,)
    return space_packet, frame

def preview():
    print_header("SPACE PACKET PREVIEW")
    try:
        space_packet, frame = build_packets()
    except (ValueError, TypeError, KeyError) as exc:
        print(f"  ERROR: {exc}")
        exit(1)
    print("GENERATED SPACE PACKET")
    print(underline)
    print(f"  Length : {len(space_packet)} bytes")
    print(f"  HEX    : {space_packet.hex(' ')}")
    print("\nGENERATED TC FRAME")
    print(underline)
    print(f"  Length : {len(frame)} bytes")
    print(f"  HEX    : {frame.hex(' ')}")
    decode_tc_frame(frame, title="TX TRANSFER FRAME DECODER")

if __name__ == "__main__":
    preview()
