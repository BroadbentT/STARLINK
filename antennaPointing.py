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

import socket
import sys
import json
import re

from datetime import datetime, timezone, timedelta
from skyfield.api import EarthSatellite, load, wgs84

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------


config = json.loads(sys.argv[1])

host = config["host"]
port = int(config["port"])
SPACECRAFT_ID = int(config["spacecraft_id"])
VIRTUAL_CHANNEL_ID = int(config["virtual_channel_id"])
APID = int(config["apid"])
payload = config["payload"]
USER_PAYLOAD = payload.encode("utf-8") if isinstance(payload, str) else payload

VISIBILITY = 30.0
SEARCH_HOURS = 48

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def recv_until_challenge(sock, timeout=10):
    """
    Read until the server has supplied a complete challenge.
    The server may split the response across multiple TCP packets,
    so keep receiving until the challenge prompt is present.
    """
    sock.settimeout(timeout)
    data = b""
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            return data.decode(errors="replace"), False
        data += chunk
        text = data.decode(errors="replace")
        if "Where will it be next?>" in text:
            return text, True

def parse_challenge(text):
    """
    Extract TLE and ground-station coordinates.
    """
    m1 = re.search(
        r"^1\s+\d+U.*$",
        text,
        re.MULTILINE
    )
    m2 = re.search(
        r"^2\s+\d+\s+.*$",
        text,
        re.MULTILINE
    )
    station = re.search(
        r"\(Lat,Long\):\s*"
        r"([-+0-9.eE]+)\s*,\s*"
        r"([-+0-9.eE]+)",
        text
    )
    if not m1 or not m2 or not station:
        return None
    tle1 = m1.group(0).strip()
    tle2 = m2.group(0).strip()
    lat = float(station.group(1))
    lon = float(station.group(2))
    return tle1, tle2, lat, lon

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
    previous_alt, _ = elevation_azimuth(satellite,station,ts,previous_time)
    current = start + step
    while current <= end:
        current_alt, _ = elevation_azimuth(satellite,station,ts,current)
        # ------------------------------------------------------
        # Rising through 30 degrees
        # ------------------------------------------------------
        if (
            previous_alt < VISIBILITY
            and current_alt >= VISIBILITY
        ):
            rise = refine_rising(satellite,station,ts,previous_time,current)
            # --------------------------------------------------
            # Find the corresponding setting crossing
            # --------------------------------------------------
            set_previous_time = current
            set_previous_alt = current_alt
            set_current = current + step
            while set_current <= end:
                set_alt, _ = elevation_azimuth(satellite,station,ts,set_current)
                if (set_previous_alt >= VISIBILITY and set_alt < VISIBILITY):
                    set_time = refine_setting(satellite, station,ts, set_previous_time,set_current)
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

def solve_challenge(tle1,tle2,lat,lon):
    """
    Calculate the first 60 integer-second positions
    after the next 30-degree contact begins.
    """
    ts = load.timescale()
    satellite = EarthSatellite(tle1,tle2,"DIGITWIN HTB",ts)
    station = wgs84.latlon(latitude_degrees=lat,longitude_degrees=lon)
    now = datetime.now(timezone.utc)
    window = find_next_window(satellite,station,ts,now)
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
    first_second = (rise.replace(microsecond=0) + timedelta(seconds=1))
    points = []
    for i in range(60):
        dt = (first_second + timedelta(seconds=i))
        alt, az = elevation_azimuth(satellite,station,ts,dt)
        points.append(f"{alt:.4f}:{az:.4f}")
    return first_second, points

def main():
    print(f"[+] Connecting to {host}:{port}")
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)
    try:
        # ======================================================
        # Persistent challenge loop
        #
        # Sat 1 -> Sat 2 -> Sat 3 -> ...
        #
        # Keep the SAME TCP connection.
        # ======================================================
        while True:
            try:
                text, alive = recv_until_challenge(sock)
            except socket.timeout:
                print("[!] Server timed out.")
                break
            except ConnectionResetError:
                print("[!] Connection reset by server.")
                break
            except OSError as e:
                print(f"[!] Socket error: {e}")
                break
            if text:
                print(text, end="")
            if not alive:
                print("[+] Server closed connection.")
                break
            parsed = parse_challenge(text)
            if parsed is None:
                print("[!] Could not parse challenge.")
                break
            tle1, tle2, lat, lon = parsed
            print()
            print("[+] TLE:")
            print(tle1)
            print(tle2)
            print(
                f"[+] Station: {lat}, {lon}"
            )
            # --------------------------------------------------
            # Solve
            # --------------------------------------------------
            try:
                result = solve_challenge(tle1,tle2,lat,lon)
            except Exception as e:
                print(
                    f"[!] Calculation error: {e}"
                )
                break
            # --------------------------------------------------
            # No visibility window
            # --------------------------------------------------
            if result is None:
                print("[+] No contact window found.")
                # Challenge representation for zero windows.
                print("[+] Sending empty response")
                sock.sendall(b"\n")
                continue
            # --------------------------------------------------
            # 60 pointing positions
            # --------------------------------------------------
            first_second, points = result
            print("[+] First contact second: " f"{first_second.isoformat()}")
            print(f"[+] Sending {len(points)} points:")
            answer = " ".join(points)
            print(answer)
            sock.sendall((answer + "\n").encode())
            print("[+] Answer sent; waiting for next challenge...")
    finally:
        sock.close()
        print("[+] Connection closed.")

if __name__ == "__main__":
    main()