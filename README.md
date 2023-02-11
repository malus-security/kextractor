# Kextractor - kernel cache manipulation library

Python library for viewing and extracting kernel extensions from a given iOS
kernel cache. It is currently available for both Linux and macOS.

Note that the kernel cache should be decompressed and decrypted (if needed) before
Kextractor is used. For versions starting from iOS 10, the kernel cache is not
encrypted. The compression algorithm used for versions up to iOS 14 is LZSS, and
for iOS 14 onwards the compression changed to BVX2.

## Instalation

In order to install the library you should first install `lief` with python
bindings and then use:

```bash
$ sudo ./setup.py install
```
You might get this error:

**No module named defusedxml.xmlrpc**

If that is the case, you need to install `defusedxml` with python bindings.

You also need to make sure you can run perl scripts and have installed
`Crypt::Rijndael` perl module. Before runing `kextractor`, please make
sure you can run `decrypt.pl` by making it an executable and that you
run the `make` command in the `/kextractor/kextractorlib/lzssdec`
directory.

After completing these steps you can use `kextractor` script from the
`/scripts` directory.

## Usage

```bash

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

`KCACHE` is the path to the decrypted kernel cache file. If you use `kextractor`
without any optional argument, it will extract all kernel extensions from cache.
This option is more time consuming for the most recent iOS versions. 
```bash
	$ kextractor KCACHE
```
If you only want to target a certain extension, you should use the `-K`
argument followed by the name of the targeted extension:
```bash
	$ kextractor -K <name_of_extension> KCACHE
```
Kextractor also has a decompression feature integrated. For that, you need to provide a path that will be used when generating the decompressed file and you need to install `pyliblzfse`(https://github.com/ydkhatri/pyliblzfse). Please note that for iOS <= 8 the kernel cache file is encrypted and it needs to be decrypted before the extensions can be extracted. Kextractor now offers this functionality, and you
will need to provide the Key and IV for the kernel cache. You can find those here: https://www.theiphonewiki.com/wiki.

## Supported iOS versions

Kextractor is currently working for every iOS version up to iOS 15.

