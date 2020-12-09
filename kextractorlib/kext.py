import lief
import pprint

class KernelExtensionPrelinkInfo:
    """Information from the prelink segment
    """

    def __init__(self, data: dict):
        self.data = data

    def get_id(self):
        return self.data['CFBundleIdentifier']

    def get_name(self):
        return self.data['CFBundleName'] \
            if 'CFBundleName' in self.data else None

    def get_vaddr(self):
        if '_PrelinkExecutable' in self.data:
            return self.data['_PrelinkExecutable']
        if '_PrelinkExecutableLoadAddr' in self.data:
            return self.data['_PrelinkExecutableLoadAddr']
        return None

    def get_size(self):
        if '_PrelinkExecutableSize' in self.data:
            return self.data['_PrelinkExecutableSize']
        return None

    def __str__(self):
        return pprint.pformat(self.data)


class KernelExtension:
    """ Kernel Extensions(Modules) from MachO binary
    """

    def __init__(self, binary: lief.MachO.Binary,
            extid: str, vaddr: int, size: int, name: str = None,
            prelink_info: KernelExtensionPrelinkInfo = None):
        assert size > 0
        assert extid != None
        assert vaddr != None
        self.prelink_info = prelink_info
        self.id = extid
        self.vaddr = vaddr
        self.size = size
        self.binary = binary
        self.name = name

    def get_id(self):
        return self.id

    def get_name(self):
        return self.name

    def get_vaddr(self):
        return self.vaddr

    def get_file_offset(self):
        return self.binary.virtual_address_to_offset(self.vaddr)

    def get_content(self):
        return bytes(self.binary.get_content_from_virtual_address(
            self.vaddr, self.size))

    def __str__(self):
        return '{} ({}) virtaddr={:#x} fileoffset={:#x} size={:#x}'.format(
            self.id,
            self.name if self.name != None else '',
            self.vaddr,
            self.get_file_offset(),
            self.size)

    def __repr__(self):
        return '<{} vaddr={:#x} size={:#x}>'.format(
            self.__class__.__name__, self.vaddr, self.size)

    def print_prelink_info(self):
        return str(self.prelink_info)
