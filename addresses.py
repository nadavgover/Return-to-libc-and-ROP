import struct


def address_to_bytes(address):
    """Convert an address to bytes, in little endian."""
    return struct.pack('<L', address)


########### QUESTION 1 ##############

# Memory address of "/bin/sh" in `libc`.
# USE THIS IN `q1b.py` AND `q1c.py`.
LIBC_BIN_SH = 0xb7d7da0b

# Memory address of the `system` function. This function is not in the PLT of
# the program, so you will have to find it's address in libc. Use GDB :)
# USE THIS IN `q1c.py`.
SYSTEM = 0xb7c5cda0

# Memory address of the `exit` function. This function is also not in the PLT,
# you'll need to find it's address in libc.
# USE THIS IN `q1c.py`.
EXIT = 0xb7c509d0

########### QUESTION 2 ##############

# Memory address of the start of the `.text` section of `libc`.
# The code in q2.py will automatically use this.
LIBC_TEXT_START = 0xb7c39750

########### QUESTION 3 ##############

# Memory address of the `auth` variable in the sudo program.
# USE THIS IN `q3.py`.
AUTH = 0x804a054

# original return address of check_address function
ORIGINAL_RA_CHECK_PASSWORD = 0x080488c6

########### QUESTION 4 ##############

# Memory address of the `puts` function. You can find the address of this
# function either in the PLT or in libc.
# USE THIS IN `q4.py`.
PUTS = 0xb7c81ca0
ADDRESS_OF_STRING = 0xbfffe0e8
ADDRESS_OF_LOOP = 0xbfffe0d4
