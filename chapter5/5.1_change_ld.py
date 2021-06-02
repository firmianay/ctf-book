import os
import argparse
from pwn import *

def change_ld(binary, ld, output):
    if not binary or not ld or not output:
        log.failure("Try 'python change_ld.py -h' for more information.")
        return None

    binary = ELF(binary)
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP")
                return None
            binary.write(addr, "/lib64/ld-glibc-{}".format(ld).ljust(size, '\0'))
            if os.access(output, os.F_OK):
                os.remove(output)
            binary.save(output)
            os.chmod(output, 0b111000000) # rwx------
    success("PT_INTERP has changed. Saved temp file {}".format(output)) 

parser = argparse.ArgumentParser(description='Force to use assigned new ld.so by changing the binary')
parser.add_argument('-b', dest="binary", help='input binary')
parser.add_argument('-l', dest="ld", help='ld.so version')
parser.add_argument('-o', dest="output", help='output file')
args = parser.parse_args()

change_ld(args.binary, args.ld, args.output)
