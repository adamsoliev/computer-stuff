#!/usr/bin/python3

import sys
from elftools.elf.elffile import ELFFile
import glob
import binascii

"""
    -----------------------
            ELF header
    -----------------------
      Program header table
    -----------------------
            Segment 1
    -----------------------
            Segment 2
    -----------------------
                ...
    -----------------------
      Section header table
    -----------------------

    Program header table - describes a segment(s). A segment contains one or more sections
    Section header table - lets one locate all the file's sections

    # Tool Interface Standard (TIS) Executable and Linking Format (ELF) Specification Version 1.2
    https://refspecs.linuxfoundation.org/elf/elf.pdf
"""

"""
RISC-V Registers
---------------------------------------------------------
#       Name     Binary      Usage
---------------------------------------------------------
x0      zero     00000      Hard-wired zero
x1      ra       00001      Return address
x2      sp       00010      Stack pointer
x3      gp       00011      Global pointer
x4      tp       00100      Thread pointer
x5      t0       00101      Temporaries
x6      t1       00110      (Caller-save registers)
x7      t2       00111
x8      s0/fp    01000      Saved register / Frame pointer
x9      s1       01001      Saved register
x10     a0       01010      Function arguments /
x11     a1       01011      Return values
x12     a2       01100      Function arguments
x13     a3       01101
x14     a4       01110
x15     a5       01111
x16     a6       10000      Function arguments
x17     a7       10001
x18     s2       10010      Saved registers
x19     s3       10011      (Callee-save registers)
x20     s4       10100
x21     s5       10101
x22     s6       10110
x23     s7       10111
x24     s8       11000
x25     s9       11001
x26     s10      11010
x27     s11      11011
x28     t3       11100      Temporaries
x29     t4       11101      (Caller-save registers)
x30     t5       11110
x31     t6       11111
pc                          Program counter

http://csl.snu.ac.kr/courses/4190.307/2020-1/riscv-user-isa.pdf
---------------------------------------
"""

regnames = ["x0", "ra", "sp", "gp", "tp"] + ["t%d" % i for i in range(0, 3)] + ["s0", "s1"] + [
    "a%d" % i for i in range(0, 8)] + ["s%d" % i for i in range(2, 12)] + ["t%d" % i for i in range(3, 7)] + ["PC"]


def print_elf(test_loc):
    # print(f"Mapping between segments and sections in the file {sys.argv[1]}")
    elffile = ELFFile(open(test_loc, 'rb'))
    print(elffile.header)

    # Segments
    print("\nProgram Headers (Segments)")
    seg_formatter = "{: <12}" * 8
    print(seg_formatter.format("Type", "Offset", "Vaddr",
          "Paddr", "FileSiz", "MemSiz", "Flags", "Align"))
    for segment in elffile.iter_segments():
        print(seg_formatter.format(
              segment.header['p_type'],
              hex(segment.header['p_offset']),
              hex(segment.header['p_vaddr']),
              hex(segment.header['p_paddr']),
              hex(segment.header['p_filesz']),
              hex(segment.header['p_memsz']),
              hex(segment.header['p_flags']),
              hex(segment.header['p_align'])))

    # Sections
    # Container({'sh_name': 27, 'sh_type': 'SHT_PROGBITS', 'sh_flags': 6, 'sh_addr': 2147483648, 'sh_offset': 4096, 'sh_size': 1724, 'sh_link': 0,
    # 'sh_info': 0, 'sh_addralign': 64, 'sh_entsize': 0})
    print("\nSection Headers")
    sec_formatter = "{: <14}" * 10
    print(sec_formatter.format("Name", "Type", "Flags", "Addr",
          "Offset", "Size", "Link", "Info", "Addralign", "EntSiz"))
    for section in elffile.iter_sections():
        if (section.header['sh_name'] == 0):  # null section
            continue
        print(sec_formatter.format(
              hex(section.header['sh_name']),
              section.header['sh_type'],
              hex(section.header['sh_flags']),
              hex(section.header['sh_addr']),
              hex(section.header['sh_offset']),
              hex(section.header['sh_size']),
              hex(section.header['sh_link']),
              hex(section.header['sh_info']),
              hex(section.header['sh_addralign']),
              hex(section.header['sh_entsize'])))
        if (hex(section.header['sh_name']) == '0x1b'):
            print(binascii.hexlify(section.data()))

        # print(section.name)
        # print(section.header['sh_size'])
        # print(binascii.hexlify(section.data()))
    print("==================================================================")


def tests():
    print(regnames)
    for x in glob.glob("/home/adam/dev/riscv-tests/isa/rv32ui-p-add"):
        if (x.endswith('.dump')):
            continue
        with open(x, 'rb') as f:
            print("test", x)
            print_elf(x)


def main():
    tests()


if __name__ == '__main__':
    main()
