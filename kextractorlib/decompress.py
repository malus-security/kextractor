import liblzfse
import subprocess
import os
import sys
import struct

def offsets(file):
    offset = 0
    with open(file, 'rb') as f:
        while True:
            buf = f.read(16)
            if buf == "":
                break
            if len(buf) < 16:
                break
            for i in range(0, 16):
                if buf[i] == 0xff and i+4 < 16:
                    chunk = struct.unpack("<I", buf[i+1:i+5])[0]
                    if chunk == 0xfeedface or chunk == 0xfeedfacf:
                        return (offset+i)
            offset += 16
        return None

def get_offsets(file):
	with open(file, 'rb') as f:
		file_to_read = f.read()
		x = offsets(file)
		if(x != None):
			return [x]
		else:
			first = file_to_read.find(b'\x62\x76\x78\x32')
			second = file_to_read.find(b'\x62\x76\x78\x24')
			f.close()
			return [first, second]
		return None

def decompress_func(file):
    directory = input("Input path of output directory (make sure it ends with / ): ")
    offsets_list = get_offsets(file)
    enc = open(file,'rb')
    output_path = str(directory + "decompressed_kernel.mach.arm")
    dec_file = open(output_path,'wb')
    lzssdec_path = str(os.path.abspath("../kextractorlib")  + "/lzssdec/lzssdec")
    if len(offsets_list) == 1:
        subprocess.run(f'"{lzssdec_path}" -o "{str(offsets_list[0])}" < "{file}" > "{output_path}"', shell=True)
        enc.close()
        return output_path
    else:
        enc.seek(int(offsets_list[0]))
        enc_file=enc.read(int(offsets_list[1]))
        try:
            dec = liblzfse.decompress(enc_file)
            dec_file.write(dec)
        except liblzfse.error:
            print('liblzfse had an error!')
        enc.close()
        return output_path