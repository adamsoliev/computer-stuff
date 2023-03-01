#!/usr/bin/python3

import sys
from elftools.elf.elffile import ELFFile
import glob
import binascii
import subprocess
from enum import Enum
import struct

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
x5      t0       00101      Temporaries/alternate link register
x6      t1       00110      Temporaries
x7      t2       00111
x8      s0/fp    01000      Saved register/Frame pointer
x9      s1       01001      Saved register
x10     a0       01010      Function arguments/Return values
x11     a1       01011
x12     a2       01100      Function arguments
x13     a3       01101
x14     a4       01110
x15     a5       01111
x16     a6       10000
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

"""
RISC-V Instruction-Set
http://blog.translusion.com/images/posts/RISC-V-cheatsheet-RV32I-4-3.pdf

RV32I Base Instruction Set - 130

Figure 2.2: RISC-V base instruction formats
------------------------------------------------------------------------------------------
31                   25 24    20 19   15 14     12 11                7 6       0
------------------------------------------------------------------------------------------
   funct7              | rs2    | rs1   | funct3  |       rd          | opcode | R-type
---------------------------------------------------------------------------------------
imm[11:0]                       | rs1   | funct3  |       rd          | opcode | I-type
---------------------------------------------------------------------------------------
imm[11:5]              | rs2    | rs1   | funct3  | imm[4:0]          | opcode | S-type
---------------------------------------------------------------------------------------
imm[31:12]                                        |       rd          | opcode | U-type
----------------------------------------------------------------------------------------
imm[12] imm[10:5]      | rs2    | rs1   | funct3  | imm[4:1] imm[11]  | opcode | B-type
---------------------------------------------------------------------------------------
imm[20] imm[10:1] imm[11] imm[19:12]              |       rd          | opcode | J-type
------------------------------------------------------------------------------------------
"""


class Funct7(Enum):
    ADD = 0b0000000
    SUB = 0b0100000


class Funct3(Enum):
    ADD = SUB = 0b000


class OP(Enum):
    ADD = SUB = 0b0110011
    JAL = 0b1101111
    ECALL = 0b1110011


regnames = ["x0", "ra", "sp", "gp", "tp"] + ["t%d" % i for i in range(0, 3)] + ["s0", "s1"] + [
    "a%d" % i for i in range(0, 8)] + ["s%d" % i for i in range(2, 12)] + ["t%d" % i for i in range(3, 7)] + ["PC"]

memory = None
PC = 32


class Regfile:
    def __init__(self):
        self.regs = [0] * 33

    def __getitem__(self, key):  # __and__ enable get/set via []
        return self.regs[key]

    def __setitem__(self, key, value):
        if (key == 0):
            return
        self.regs[key] = value & 0xFFFFFFFF  # mask off bits beyond 32


def init():
    global memory, regfile
    # 16kb memory
    memory = b'\x00' * 0x4000
    regfile = Regfile()


def load(addr, data):
    global memory
    addr -= 0x80000000
    assert addr >= 0 and addr < len(memory)
    memory = memory[:addr] + data + memory[addr + len(data):]


def readelf(args):
    subprocess.call(args)


"""
    process execution cycle
        fetch
        decode
        execute

1101111 00000 0000000000000000101
JAL     rd    imm
              5 (x5/t0)
"""


def fetch(addr):
    assert addr >= 0 and addr < len(memory)
    # print(memory[addr:addr + 4].hex())
    return struct.unpack(">I", memory[addr:addr + 4])[0]


def execute():
    global PC
    regfile[PC] -= 0x80000000
    for i in range(20):
        instr = fetch(regfile[PC])
        # *** Decode ***
        op = OP(instr >> 24)
        print(op)

        # move PC
        regfile[PC] += 0x4

    """
    regfile[PC] points to the next instr
        // fetch next instr
        // process
    """
    return False


def tests():
    for x in glob.glob("/home/adam/dev/riscv-tests/isa/rv32ui-p-add"):
        if (x.endswith('.dump')):
            continue
        with open(x, 'rb') as f:
            # readelf(["readelf", x, "-e"])
            print("test", x)
            init()
            elffile = ELFFile(f)
            for segment in elffile.iter_segments():
                if (segment.header.p_paddr < 0x80000000):
                    continue
                load(segment.header.p_paddr, segment.data())
                # print(segment.header.p_paddr, binascii.hexlify(segment.data()))
            regfile[PC] = 0x80000000
            instrcnt = 0
            while execute():
                instrcnt += 1
            print("run %d instructions" % instrcnt)


def main():
    tests()


if __name__ == '__main__':
    main()
