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

from pwn import hexdump,log,remote
import argparse
import struct
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
    parser = argparse.ArgumentParser(description="Spacecraft packet sender")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
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
        "spacecraft_id": args.spacecraft_id,
        "virtual_channel_id": args.virtual_channel_id,
        "apid": args.apid,
        "payload": args.payload,
        "packet_count": args.packet_count,
        "tc_packet_count": args.tc_packet_count,
    }

host = config["host"]
port = int(config["port"])
spacecraft_id = int(config["spacecraft_id"])
virtual_channel_id = int(config["virtual_channel_id"])
apid = int(config["apid"])
user_payload = config["payload"].encode("utf-8")
packet_count = int(config["packet_count"])
tc_packet_count = int(config["tc_packet_count"])

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def generate_space_packet(apid: int, packet_count: int, payload: bytes) -> bytes:
    version = 0
    packet_type = 1
    secondary_header_flag = 0
    sequence_flags = 0b11
    packet_id = ((version << 13)|(packet_type << 12)|(secondary_header_flag << 11)|(apid & 0x7FF))
    sequence_control = (sequence_flags << 14) | (packet_count & 0x3FFF)
    packet_data_length = len(payload) - 1
    return struct.pack(">HHH", packet_id, sequence_control, packet_data_length) + payload

def generate_tc_frame(spacecraft_id: int,virtual_channel_id: int,tc_packet_count: int,payload: bytes,) -> bytes:
    version = 0
    bypass_flag = 1
    control_command_flag = 0
    reserved = 0
    first_word = ((version << 14)|(bypass_flag << 13)|(control_command_flag << 12)|(reserved << 10)|(spacecraft_id & 0x3FF))
    total_len = 5 + len(payload) + 2
    frame_length = total_len - 1
    second_word = ((virtual_channel_id & 0x3F) << 10) | (frame_length & 0x3FF)
    frame_without_fecf = struct.pack(">HHB", first_word, second_word, tc_packet_count & 0xFF) + payload
    fecf = crc16_ccitt_false(frame_without_fecf)
    return frame_without_fecf + struct.pack(">H", fecf)

def tmTeleCommand():
    space_packet = generate_space_packet(apid=apid,packet_count=0,payload=user_payload,)
    frame = generate_tc_frame(spacecraft_id=spacecraft_id,virtual_channel_id=virtual_channel_id,tc_packet_count=0,payload=space_packet,)
    log.info(f"Space Packet length: {len(space_packet)} bytes")
    log.info(f"TC frame length: {len(frame)} bytes")
    log.info(hexdump(frame))
    r = remote(host,port)
    r.send(frame)
    response = r.recvall(timeout=3)
    log.info(f"Server response: {response!r}")
    r.close()

if __name__ == "__main__":
    tmTeleCommand()