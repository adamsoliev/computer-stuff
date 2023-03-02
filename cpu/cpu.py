#!/usr/bin/python3

import sys
from elftools.elf.elffile import ELFFile
import glob
import binascii
import subprocess
from enum import Enum
import struct


class Funct7(Enum):
    ADD = 0b0000000
    SUB = 0b0100000


class Funct3(Enum):
    JALR = BEQ = LB = SB = ADDI = ADD = SUB = FENCE = ECALL = EBREAK = 0b000
    BNE = LH = SH = SLLI = SLL = 0b001
    BLT    = 0b100
    BGE    = 0b101
    BLTU   = 0b110
    BGEU   = 0b111
    LW     = 0b010
    LBU    = 0b100
    LHU    = 0b101
    SW     = 0b010
    SLTI   = 0b010
    SLTIU  = 0b011
    XORI   = 0b100
    ORI    = 0b110
    ANDI   = 0b111
    SRLI   = 0b101
    SRAI   = 0b101
    SLT    = 0b010
    SLTU   = 0b011
    XOR    = 0b100
    SRL    = 0b101
    SRA    = 0b101
    OR     = 0b110
    AND    = 0b111

class OP(Enum):
    LUI = 0b0110111
    AUIPC = 0b0010111
    JAL = 0b1101111
    JALR = 0b1100111
    BRANCH = 0b1100011
    LOAD = 0b0000011
    STORE = 0b0100011
    OP_IMM = 0b0010011
    OP = 0b0110011
    MISC_MEM = 0b0001111
    SYSTEM = 0b1110011


class Type(Enum):
    R = 0
    I = 1
    S = 2
    U = 3
    B = 4
    J = 5
    OTHER = 6

    def findType(op):
        if (op in [OP.OP]):
            return Type.R
        if (op in [OP.JALR, OP.LOAD, OP.OP_IMM]):
            return Type.I
        if (op in [OP.STORE]):
            return Type.S
        if (op in [OP.LUI, OP.AUIPC]):
            return Type.U
        if (op in [OP.BRANCH]):
            return Type.B
        if (op in [OP.JAL]):
            return Type.J
        if (op in [OP.MISC_MEM, OP.SYSTEM]):
            return Type.OTHER


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


def fetch(addr):
    assert addr >= 0 and addr < len(memory)
    return struct.unpack("<I", memory[addr:addr + 4])[0]


def extractBits(instr, s, e):
    """
        imagine you have 32-bit int. how do you extract 5-10th bits?
            mask:
                generate 100000 (note 5 0s) and then 011111 (note 5 1s)
                         1 << 5 (s - e + 1)          (100000) - 1
            apply:
                int >> 5 (= shift the int to the right by 5 to ignore the first 5 bits that we dont care about)
                int & mask (= ignoring bits beyong 10th bit while keeping 5-10th)
    """
    result = (instr >> e) & ((1 << (s - e + 1)) - 1)
    return result


def execute():
    global PC
    regfile[PC] -= 0x80000000
    for i in range(10):
        instr = fetch(regfile[PC])
        # *** Decode ***
        op = OP(extractBits(instr, 6, 0))
        type = Type.findType(op)
        if (type == Type.R):
            pass
        elif (type == Type.I):
            funct3 = Funct3(extractBits(instr, 14, 12))
            rs1 = extractBits(instr, 19, 15)
            imm = extractBits(instr, 31, 20)
            print(funct3, regnames[rs1], imm)

        elif (type == Type.S):
            pass
        elif (type == Type.U):
            pass
        elif (type == Type.B):
            pass
        elif (type == Type.J):
            rd = extractBits(instr, 11, 7)
            imm = extractBits(instr, 31, 12)
        elif (type == Type.OTHER):
            pass

        print("{: <10} {: <2} {: <10} {: <10}".format(
            hex(instr), "->", op, type))

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

"""
    Object File Format
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
RV32I Base Instruction Set - 130

RISC-V Instruction-Set
http://blog.translusion.com/images/posts/RISC-V-cheatsheet-RV32I-4-3.pdf

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

"""
                            RV32I Base Instruction Set
-------------------------------------------------------------------------------------------------
imm[31:12]                                                      rd              0110111    LUI
imm[31:12]                                                      rd              0010111    AUIPC
imm[20|10:1|11|19:12]                                           rd              1101111    JAL
imm[11:0]                       rs1         000                 rd              1100111    JALR
imm[12|10:5]        rs2         rs1         000            imm[4:1|11]          1100011    BEQ
imm[12|10:5]        rs2         rs1         001            imm[4:1|11]          1100011    BNE
imm[12|10:5]        rs2         rs1         100            imm[4:1|11]          1100011    BLT
imm[12|10:5]        rs2         rs1         101            imm[4:1|11]          1100011    BGE
imm[12|10:5]        rs2         rs1         110            imm[4:1|11]          1100011    BLTU
imm[12|10:5]        rs2         rs1         111            imm[4:1|11]          1100011    BGEU
imm[11:0]                       rs1         000                 rd              0000011    LB
imm[11:0]                       rs1         001                 rd              0000011    LH
imm[11:0]                       rs1         010                 rd              0000011    LW
imm[11:0]                       rs1         100                 rd              0000011    LBU
imm[11:0]                       rs1         101                 rd              0000011    LHU
imm[11:5]           rs2         rs1         000              imm[4:0]           0100011    SB
imm[11:5]           rs2         rs1         001              imm[4:0]           0100011    SH
imm[11:5]           rs2         rs1         010              imm[4:0]           0100011    SW
imm[11:0]                       rs1         000                 rd              0010011    ADDI
imm[11:0]                       rs1         010                 rd              0010011    SLTI
imm[11:0]                       rs1         011                 rd              0010011    SLTIU
imm[11:0]                       rs1         100                 rd              0010011    XORI
imm[11:0]                       rs1         110                 rd              0010011    ORI
imm[11:0]                       rs1         111                 rd              0010011    ANDI
0000000             shamt       rs1         001                 rd              0010011    SLLI
0000000             shamt       rs1         101                 rd              0010011    SRLI
0100000             shamt       rs1         101                 rd              0010011    SRAI
0000000             rs2         rs1         000                 rd              0110011     ADD
0100000             rs2         rs1         000                 rd              0110011    SUB
0000000             rs2         rs1         001                 rd              0110011    SLL
0000000             rs2         rs1         010                 rd              0110011    SLT
0000000             rs2         rs1         011                 rd              0110011    SLTU
0000000             rs2         rs1         100                 rd              0110011    XOR
0000000             rs2         rs1         101                 rd              0110011    SRL
0100000             rs2         rs1         101                 rd              0110011    SRA
0000000             rs2         rs1         110                 rd              0110011    OR
0000000             rs2         rs1         111                 rd              0110011    AND
fm       pred        succ       rs1         000                 rd              0001111    FENCE
000000000000                   00000        000                 00000           1110011    ECALL
000000000001                   00000        000                 00000           1110011    EBREAK
-------------------------------------------------------------------------------------------------
"""
