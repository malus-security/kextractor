#!/usr/bin/env python3

import sys
import struct


def main():
	if len(sys.argv) != 2:
		print >> sys.stderr, "Usage: $0 <decrypted.kernelcache>"
		sys.exit(1)

with open(sys.argv[1], 'rb') as f:
	file_to_read = f.read()
	print("First offset: " + str(file_to_read.find(b'\x62\x76\x78\x32')))
	print("Second offset: " + str(file_to_read.find(b'\x62\x76\x78\x24')))

if __name__ == "__main__":
	sys.exit(main())