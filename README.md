# kEXTractor - kernel cache manipulation library

Python library for viewing and extracting kernel extensions from a given iOS
kernel cache.


In order to install the library you should first install `lief` with python
bindings and then use:

```bash
$ sudo ./setup.py install
```

After installing the library you can use `kextractor` script.

```bash
$ kextractor -h

usage: kextractor [-h] [-K KEXT] [-k] [-o OUTDIR] KCACHE

Kernel cache manipulation tool

positional arguments:
  KCACHE                path to decrypted kernel cache

optional arguments:
  -h, --help            show this help message and exit
  -K KEXT, --extract-kext KEXT
                        extract kernel extension from kernel cache
  -k, --show-kexts      show kernel extensions in kernel cache
  -o OUTDIR, --output-dir OUTDIR
                        store data to given directory
```
