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

import subprocess
import binascii
import sys

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# Note    : Data recovered from the EEPROM dump
# -------------------------------------------------------------------------------------

KEY = "INSERT HERE"
IV = "INSERT HERE"
CIPHERTEXT = "INSERT HERE"

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def decrypt():
    try:
        ciphertext = binascii.unhexlify(CIPHERTEXT)
    except ValueError:
        print("[-] Invalid ciphertext hex")
        sys.exit(1)
    cmd = ["openssl","enc","-d","-aes-256-cbc","-K", KEY,"-iv", IV,]
    try:
        result = subprocess.run(cmd,input=ciphertext,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,)
    except FileNotFoundError:
        print("[-] OpenSSL is not installed.")
        print("    Install it with: sudo apt install openssl")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("[-] Decryption failed:")
        print(e.stderr.decode(errors="replace"))
        sys.exit(1)
    plaintext = result.stdout
    print("[+] AES-256-CBC decryption successful")
    print()
    print("[+] Hex:")
    print(plaintext.hex())
    print()
    print("[!] Plaintext:")
    print(plaintext.decode(errors="replace"))
    print()

if __name__ == "__main__":
    decrypt()