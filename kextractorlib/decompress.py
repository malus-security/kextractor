#!/usr/bin/env python

import liblzfse

output_file=input("Path of output file: ")
file=input("Path of file to decompress: ")
offset1=input("First offset: ")
offset2=input("Second offset: ")
enc = open(file,'rb')
dec_file = open(output_file,'wb')
enc.seek(int(offset1))
enc_file=enc.read(int(offset2))
try:
    dec = liblzfse.decompress(enc_file)
    dec_file.write(dec)
except liblzfse.error:
    print('liblzfse had an error!')
enc.close()
    