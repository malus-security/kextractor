import subprocess
import os
import sys
import struct

def decrypt(file):
    with open(file, 'rb') as f:
        buf = f.read(4)
        if buf == b'\x33\x67\x6d\x49':
            f.close()
            key = input("Input file key: ")
            iv = input("Input file IV: ")
            decode_path = str(os.path.abspath("../kextractorlib")  + "/decodeimg3.pl")
            subprocess.run(f'"{decode_path}" "{file}" -o "{file}" -k "{key}" -iv "{iv}" 1 > /dev/null', shell=True)
        else:
            return