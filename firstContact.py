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
import math
import json
import sys
import re

from datetime import datetime, timedelta, timezone
from sgp4.api import Satrec
from sgp4.api import jday

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

ELEVATION_THRESHOLD = 30.0
SEARCH_SECONDS = 24 * 60 * 60
STEP_SECONDS = 10


# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def propagate(sat, dt):
    """Return satellite TEME position in km."""
    jd, fr = jday(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.second + dt.microsecond / 1e6,)
    error, position, velocity = sat.sgp4(jd, fr)
    if error != 0:
        raise RuntimeError(f"SGP4 error {error}")
    return position

def gmst(dt):
    """Greenwich Mean Sidereal Time, radians."""
    jd, fr = jday(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.second + dt.microsecond / 1e6,)
    jd_full = jd + fr
    T = (jd_full - 2451545.0) / 36525.0
    theta = (280.46061837 + 360.98564736629 * (jd_full - 2451545.0) + 0.000387933 * T * T - T * T * T / 38710000.0)
    return math.radians(theta % 360.0)

def station_ecef(lat_deg, lon_deg):
    """Convert geodetic latitude/longitude to ECEF.WGS-84."""
    lat = math.radians(lat_deg)
    lon = math.radians(lon_deg)
    a = 6378.137
    f = 1.0 / 298.257223563
    e2 = f * (2.0 - f)
    sin_lat = math.sin(lat)
    cos_lat = math.cos(lat)
    N = a / math.sqrt(1.0 - e2 * sin_lat * sin_lat)
    x = N * cos_lat * math.cos(lon)
    y = N * cos_lat * math.sin(lon)
    z = N * (1.0 - e2) * sin_lat
    return x, y, z

def teme_to_ecef(position, dt):
    """Convert TEME coordinates to approximate ECEF.For this challenge this is sufficient for pass-window determination."""
    theta = gmst(dt)
    x, y, z = position
    c = math.cos(theta)
    s = math.sin(theta)
    # TEME -> ECEF rotation
    xe = c * x + s * y
    ye = -s * x + c * y
    ze = z
    return xe, ye, ze

"""Elevation"""

def elevation_deg(sat, station_lat, station_lon, dt):
    """Calculate satellite elevation above the horizon."""
    sat_teme = propagate(sat, dt)
    sat_ecef = teme_to_ecef(sat_teme, dt)
    sx, sy, sz = station_ecef(station_lat, station_lon)
    dx = sat_ecef[0] - sx
    dy = sat_ecef[1] - sy
    dz = sat_ecef[2] - sz
    lat = math.radians(station_lat)
    lon = math.radians(station_lon)
    # ECEF -> local ENU
    sin_lat = math.sin(lat)
    cos_lat = math.cos(lat)
    sin_lon = math.sin(lon)
    cos_lon = math.cos(lon)
    east = -sin_lon * dx + cos_lon * dy
    north = (-sin_lat * cos_lon * dx - sin_lat * sin_lon * dy + cos_lat * dz)
    up = (cos_lat * cos_lon * dx + cos_lat * sin_lon * dy + sin_lat * dz)
    horizontal = math.sqrt(east * east + north * north)
    return math.degrees(math.atan2(up, horizontal))

"""Crossing refinement"""

def refine_crossing(sat,lat,lon,low,high,threshold=ELEVATION_THRESHOLD,):
    """Binary-search a 30-degree elevation crossing."""
    low_value = elevation_deg(sat, lat, lon, low) - threshold
    high_value = elevation_deg(sat, lat, lon, high) - threshold
    for _ in range(35):
        middle = low + (high - low) / 2
        middle_value = (elevation_deg(sat, lat, lon, middle) - threshold)
        if (low_value <= 0 and middle_value <= 0) or (low_value >= 0 and middle_value >= 0):
            low = middle
            low_value = middle_value
        else:
            high = middle
            high_value = middle_value
    return low + (high - low) / 2

""" Find visibility windows """

def find_passes(sat,lat,lon,start,duration_seconds=SEARCH_SECONDS,):
    """Find all intervals where elevation >= 30 degrees.Returns: [(rise_datetime, set_datetime), ...]"""
    end = start + timedelta(seconds=duration_seconds)
    threshold = ELEVATION_THRESHOLD
    passes = []
    previous_time = start
    previous_elevation = (elevation_deg(sat, lat, lon, previous_time) - threshold)
    currently_visible = previous_elevation >= 0
    rise_time = None
    # If the satellite is already above 30 degrees,
    # this is the current window. The challenge says it
    # can be skipped, so we still detect it but mark it.
    if currently_visible:
        rise_time = start
    current = start + timedelta(seconds=STEP_SECONDS)
    while current <= end:
        current_elevation = (elevation_deg(sat, lat, lon, current) - threshold)
        # Rising through 30 degrees
        if (previous_elevation < 0 and current_elevation >= 0):
            rise_time = refine_crossing(sat,lat,lon, previous_time,current,threshold,)
        # Setting through 30 degrees
        elif (previous_elevation >= 0 and current_elevation < 0):
            set_time = refine_crossing(sat,lat,lon,previous_time,current,threshold,)
            if rise_time is not None:
                passes.append((rise_time, set_time))
            rise_time = None
        previous_time = current
        previous_elevation = current_elevation
        current += timedelta(seconds=STEP_SECONDS)
    # Satellite is still visible at the end of the window.
    if rise_time is not None:
        passes.append((rise_time, end))
    return passes


"""Formatting"""

def format_timestamp(dt):
    """Challenge timestamp format."""
    dt = dt.astimezone(timezone.utc)
    # Drop microseconds
    dt = dt.replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

"""Challenge parsing"""

def parse_challenge(text):
    """Extract:TLE line 1 TLE line 2 latitude longitude"""
    lines = text.splitlines()
    tle1 = None
    tle2 = None
    for line in lines:
        line = line.strip()
        if line.startswith("1 ") and len(line) >= 60:
            tle1 = line
        elif line.startswith("2 ") and len(line) >= 60:
            tle2 = line
    if tle1 is None or tle2 is None:
        raise ValueError("Could not find TLE")

    # Look for:(Lat,Long): 48.123,-162.456

    match = re.search(r"\(\s*Lat\s*,\s*Long\s*\)\s*:\s*"r"([-+]?\d+(?:\.\d+)?)\s*,\s*"r"([-+]?\d+(?:\.\d+)?)",text,re.IGNORECASE,)

    if not match:
        raise ValueError("Could not find station coordinates")
    lat = float(match.group(1))
    lon = float(match.group(2))
    return tle1, tle2, lat, lon

"""Solve one challenge"""

def solve_challenge(text):
    tle1, tle2, lat, lon = parse_challenge(text)
    print("[+] TLE:")
    print(tle1)
    print(tle2)
    print(f"[+] Ground station: {lat}, {lon}")
    sat = Satrec.twoline2rv(tle1, tle2)

    # Important:
    #
    # The challenge's TLE epoch determines the orbital state,
    # but the 24-hour question is normally relative to the
    # challenge's current time.
    #
    # Use UTC now.
    start = datetime.now(timezone.utc)

    passes = find_passes(sat,lat,lon,start,)

    # The challenge says:
    #
    # "you can skip the current window"
    #
    # Therefore discard a pass which started before our
    # search start.
    if passes:
        first_rise, first_set = passes[0]
        if first_rise <= start:
            passes = passes[1:]
    timestamps = []
    for rise, setting in passes:
        # Don't report an artificial "set" at the 24h boundary.
        if setting <= start + timedelta(seconds=SEARCH_SECONDS):
            timestamps.append(format_timestamp(rise))
            timestamps.append(format_timestamp(setting))
    answer = " ".join(timestamps)
    print("[+] Answer:")
    print(answer)
    return answer

""" TCP client"""

def recv_until_quiet(sock, timeout=1.0):
    """
    Read whatever the server currently sends.
    HTB challenge servers commonly send the question in
    several TCP packets, so don't assume one recv() gets
    the whole thing.
    """

    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        except socket.timeout:
            break
    return b"".join(chunks).decode(errors="replace")

def main():
    print(f"[*] Connecting to {host}:{port}")
    with socket.create_connection((host, port),timeout=10,) as sock:
        # Give the server a moment to send the question.
        sock.settimeout(3)
        while True:
            try:
                data = sock.recv(8192)
            except socket.timeout:
                print("[!] Timeout waiting for server")
                break
            if not data:
                print("[*] Server closed connection")
                break
            text = data.decode(errors="replace")
            print(text, end="")
            # Keep collecting if the TLE/station information
            # has not arrived yet.
            buffer = text
            while ("TLE:" not in buffer or "(Lat,Long):" not in buffer):
                try:
                    more = sock.recv(8192)
                except socket.timeout:
                    break
                if not more:
                    break
                more_text = more.decode(errors="replace")
                print(more_text, end="")
                buffer += more_text
            # Don't try to solve until we have both TLE lines.
            if (re.search(r"^1 .+$", buffer, re.MULTILINE) and re.search(r"^2 .+$", buffer, re.MULTILINE) and re.search( r"\(\s*Lat\s*,\s*Long\s*\)\s*:", buffer, re.IGNORECASE,)):
                try:
                    answer = solve_challenge(buffer)
                except Exception as exc:
                    print(f"[!] Failed to solve: {exc}")
                    raise
                sock.sendall((answer + "\n").encode())
                print("[+] Answer sent")
                # Wait for the next challenge.
                # The server may send more data immediately.
                continue

if __name__ == "__main__":
    main()