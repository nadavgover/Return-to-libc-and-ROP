#!/usr/bin/python

import infosec.utils


ASSEMBLY_TEMPLATE = '.intel_syntax noprefix;.globl main;main:;{data}'

ASSEMBLE = 'gcc -xassembler - -o /dev/stdout -m32 -nostdlib -emain -Xlinker --oformat=binary'


def assemble_data(data):
    return infosec.utils.execute(ASSEMBLE, ASSEMBLY_TEMPLATE.format(data=data), raise_error=True).stdout
    

def assemble_file(path):
    with open(path, 'rb') as reader:
        data = reader.read()
    return assemble_data(data)


def main(path=None, markzero=False):
    try:
        assembly = assemble_file(path)
        assembly = ''.join('\x1b[31m\\x00\x1b[0m' if markzero and c == '\x00' else ('\\x%02x' % ord(c)) for c in assembly)
        print(assembly)
    except RuntimeError as error:
        print(error)


if __name__ == '__main__':
    import os, sys

    markzero = False
    
    if '--markzero' in sys.argv[1:]:
        markzero = True
        sys.argv.remove('--markzero')

    if '--help' in sys.argv or len(sys.argv) < 2:
        name = os.path.basename(sys.argv[0])
        print('USAGE:')
        print('\t%s [--markzero] <file>' % name)
        sys.exit(1)

    main(path=sys.argv[-1], markzero=markzero)
