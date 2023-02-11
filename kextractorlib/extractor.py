import struct
import lief
import sys

from kextractorlib.kext import *
from kextractorlib.binary_utils import *
from kextractorlib.applexml_parser import parse as applexml_parse

__all__ = ['get_kernel_extensions']

PRELINK_INFO_SEG = '__PRELINK_INFO'
PRELINK_INFO_INFO_SECT = '__info'
PRELINK_INFO_KMOD_INFO_SECT = '__kmod_info'
PRELINK_INFO_KMOD_START_SECT = '__kmod_start'


def put_remain_sections(kcache_path, f, content_writed):
    kcache = lief.MachO.parse(kcache_path)
    if type(kcache) == lief.MachO.FatBinary:
        assert(kcache.size == 1)
        binary = kcache.at(0)
    else:
        binary = kcache

    kcache = lief.MachO.parse(f.name)
    if type(kcache) == lief.MachO.FatBinary:
        assert(kcache.size == 1)
        binary_kext = kcache.at(0)
    else:
        binary_kext = kcache
    
    remain_sect = []
    last_addr = 0x0
    for sect in binary_kext.sections:
        content = bytes(binary.get_content_from_virtual_address(sect.virtual_address, sect.size))
        if content not in content_writed:
            remain_sect.append(sect)
        else:
            last_addr = sect.virtual_address + sect.size
    size = len(content_writed)

    segm = binary.get_segment("__TEXT_EXEC")

    for sect in remain_sect:
        content_seg = binary.get_content_from_virtual_address(sect.segment.virtual_address, sect.segment.virtual_size)
        if bytes(content_seg) not in content_writed:
            content_writed += bytes(content_seg)
            binary_kext.get_segment(sect.segment.name).content = content_seg

    binary_kext.write(f.name)

def get_section(binary: lief.MachO.FatBinary,
        segment_name: str, section_name: str):
    """Returns the section whose name is section_name and is located inside
    the segment whose name is segment_name from the given MachO bianry.
    """
    seg = binary.get_segment(segment_name)
    if not seg:
        return None
    sects = [s for s in seg.sections if s.name == section_name]
    assert len(sects) <= 1
    return sects[0] if len(sects) > 0 else None


def get_kcache_prelink_info(binary: lief.MachO.FatBinary):
    """Returns the information from the __info section from the 
    __PRELINK_INFO segment of the given MachO binary
    """
    sect = get_section(binary, PRELINK_INFO_SEG, PRELINK_INFO_INFO_SECT)
    assert sect
    info = ''.join([chr(c) for c in sect.content])
    assert(len(info) == sect.size)
    return applexml_parse(info)


def get_possible_kexts_info(kcache_prelink_info):
    """Extract an array of information about posible kernel extections
    from the given prelink information, extracted from the __PRELINK_INFO
    segment.
    """
    if type(kcache_prelink_info) == dict:
        return kcache_prelink_info['_PrelinkInfoDictionary']
    else:
        return kcache_prelink_info


def get_kexts_info(posible_kexts_info: list):
    """Extract an array of information about kernel extension.
    Note this functions works only for iOS <=11.
    For iOS 12 the returned array will be empty.
    """
    return [x for x in posible_kexts_info if '_PrelinkExecutableSize' in x]


def get_kmod_data(binary: lief.MachO.FatBinary, kexts_info: list):
    """Extracts kernel extension from the __kmod_start and __kmod_info sections
    from a given MachO binary. This function also requires an array of possible
    kernel extensions info.
    Note the sections mentioned above are only present in iOS 12.
    """

    def vector_to_words(v):
        return struct.unpack('<{}Q'.format(len(v) // 8), v)
    def untag_pointers(v):
        return [untag_pointer(p) for p in v]

    kmod_infos = get_section(binary,
        PRELINK_INFO_SEG, PRELINK_INFO_KMOD_INFO_SECT)
    if not kmod_infos:
        return None

    kmod_starts = get_section(binary,
        PRELINK_INFO_SEG, PRELINK_INFO_KMOD_START_SECT)
    assert kmod_starts
    kmod_infos = bytes(kmod_infos.content)
    kmod_starts = bytes(kmod_starts.content)
    assert len(kmod_infos) % 8 == 0
    assert len(kmod_starts) % 8 == 0
    assert len(kmod_infos) + 8 == len(kmod_starts)
    kmod_infos = untag_pointers(vector_to_words(kmod_infos))
    kmod_starts = untag_pointers(vector_to_words(kmod_starts))
    kext_lens = [kmod_starts[i+1] - kmod_starts[i]
        for i in range(len(kmod_starts)-1)]
    kext_ids = [binary_get_string_from_address(binary, vaddr+16)
        for vaddr in kmod_infos]
    kext_vaddrs = kmod_starts[:-1]

    kext_prelink_infos = {}
    for data in kexts_info:
        prelink_info = KernelExtensionPrelinkInfo(data)
        if prelink_info.get_id() != None:
            kext_prelink_infos[prelink_info.get_id()] = prelink_info
    kexts = []
    for kid, vaddr, size in  zip(kext_ids, kext_vaddrs, kext_lens):
        if kid in kext_prelink_infos:
            prelink_info = kext_prelink_infos[kid]
        else:
            prelink_info = None
        kext = KernelExtension(
            binary,
            kid,
            vaddr,
            size,
            name=prelink_info.get_name() if prelink_info != None else None,
            prelink_info=prelink_info)
        kexts.append(kext)
    return kexts


def get_kernel_extensions(kcache_path: str):
    """Returns and array of kernel extensions from the kernel cache whose
    path is given to the function.
    """

    kcache = lief.MachO.parse(kcache_path)
    if type(kcache) == lief.MachO.FatBinary:
        assert(kcache.size == 1)
        binary = kcache.at(0)
    else:
        binary = kcache

    kcache_prelink_info = get_kcache_prelink_info(binary)
    posible_kexts_info = get_possible_kexts_info(kcache_prelink_info)
    kexts = []
    kexts_info = get_kexts_info(posible_kexts_info)

    # iOS <= 11
    if len(kexts_info) > 0:
        for data in kexts_info:
            kext_prelink_info = KernelExtensionPrelinkInfo(data)
            kext = KernelExtension(
                binary,
                kext_prelink_info.get_id(),
                kext_prelink_info.get_vaddr(),
                kext_prelink_info.get_size(),
                kext_prelink_info.get_name(),
                kext_prelink_info)
            kexts.append(kext)
        return kexts

    # iOS 12
    print("WARNING: For iOS 12 the tool is able to extract " + \
        "just the text section.", file=sys.stderr)
    kexts = get_kmod_data(binary, posible_kexts_info)
    if kexts:
        return kexts

    return []

