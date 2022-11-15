import lief

def bianary_get_word_size(binary: lief.MachO.Binary):
    """Returns the word size of a given MachO Binary.
    It return 4 for a 32bit binary and 8 for 64bit binary
    """
    assert(binary.header.magic in
        [lief.MachO.MACHO_TYPES.MAGIC, lief.MachO.MACHO_TYPES.MAGIC_64])
    return 4 if binary.header.magic == lief.MachO.MACHO_TYPES.MAGIC else 8


def binary_get_string_from_address(binary: lief.MachO.Binary, vaddr: int):
    """Returns the ascii string from the given virtual address(vaddr) of
    a given MachO binary
    """
    s = ''
    while True:
        byte = binary.get_content_from_virtual_address(vaddr, 1)
        if byte == None:
            break
        byte = byte[0]
        if byte == 0:
            break
        vaddr += 1
        s += chr(byte)
    return s


def untag_pointer(p):
    """Returns the untaged pointer. On iOS 12 the first 16 bits(MSB) of a
    pointer are used to store extra information. We asy that the pointers
    from iOS 12 are tagged. More information can be found here:
    https://bazad.github.io/2018/06/ios-12-kernelcache-tagged-pointers/
    """
    return (p & ((1 << 48) -1)) | (0xffff << 48)
