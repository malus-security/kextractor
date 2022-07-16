#!/usr/bin/env python3

import sys
import struct


def main():
	if len(sys.argv) != 2:
		print >> sys.stderr, "Usage: $0 <decrypted.kernelcache>"
		sys.exit(1)

	offset = 0
	with open(sys.argv[1], 'rb') as f:
		found1 = False
		found2 = False
		while True:
			buf = f.read(16)
			if buf == "":
				break
			if len(buf) < 16:
				break
			for i in range(0, 16):
				if i+4 < 16:
					string_buf = str(buf)
					chunk = struct.unpack("<I", buf[i+1:i+5])[0]
					if chunk == 0x32787662 and found1 == False:
						found1 = True
						print("First offset: "+ str(offset+i+1))
						break
					if chunk == 0x24787662 or 'bvx$' in string_buf:
						found2 = True
						print("Second offset: " + str(offset+i+1))
						break
			if found2 == True:
				break
			offset += 16


if __name__ == "__main__":
	sys.exit(main())