#!/usr/bin/python3

import sys
from elftools.elf.elffile import ELFFile
import glob

def elf(test_loc):
    """
    if len(sys.argv) < 2:
        print("You must provide this script with an elf binary file you want to examine")
        exit(1)
        """
    # print(f"Mapping between segments and sections in the file {sys.argv[1]}")
    elffile = ELFFile(open(test_loc, 'rb'))
    """
    for idx in range(elffile.num_segments()):
        print(elffile.get_segment(idx))
    for idx in range(elffile.num_sections()):
        print(elffile.get_section(idx))
        """
    for section in elffile.iter_sections():
        if (section.header['sh_name'] == 0): # null section
            continue
        # print(section.header)
        print(section.name)
        # print(section.stream)
        # print(section.structs)
        print(section.data())
        print("==================================================================")


def tests():
    for x in glob.glob("/home/adam/dev/riscv-tests/isa/rv32ui-p-add"):
        if (x.endswith('.dump')):
            continue
        with open(x, 'rb') as f:
            print("test", x)
            elf(x)


def main():
    tests();

if __name__ == '__main__':
    main()

