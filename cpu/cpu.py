#!/usr/bin/python3

import sys
from elftools.elf.elffile import ELFFile
import glob
import binascii
import subprocess
from enum import Enum
import struct


INSTR = {"lui":   {"opcode": 0b0110111, "type": "U", "funct3": 0xF},
         "auipc": {"opcode": 0b0010111, "type": "U", "funct3": 0xF},
         "jal":   {"opcode": 0b1101111, "type": "U", "funct3": 0xF},

         "jalr":  {"opcode": 0b1100111, "type": "I", "funct3": 0x0},

         "beq":   {"opcode": 0b1100011, "type": "B", "funct3": 0x0},
         "bne":   {"opcode": 0b1100011, "type": "B", "funct3": 0x1},
         "blt":   {"opcode": 0b1100011, "type": "B", "funct3": 0x4},
         "bge":   {"opcode": 0b1100011, "type": "B", "funct3": 0x5},
         "bltu":  {"opcode": 0b1100011, "type": "B", "funct3": 0x6},
         "bgeu":  {"opcode": 0b1100011, "type": "B", "funct3": 0x7},

         "lb":    {"opcode": 0b0000011, "type": "I", "funct3": 0x0},
         "lh":    {"opcode": 0b0000011, "type": "I", "funct3": 0x1},
         "lw":    {"opcode": 0b0000011, "type": "I", "funct3": 0x2},
         "lbu":   {"opcode": 0b0000011, "type": "I", "funct3": 0x4},

         "lhu":   {"opcode": 0b0000011, "type": "I", "funct3": 0x5},
         "sb":    {"opcode": 0b0100011, "type": "S", "funct3": 0x0},
         "sh":    {"opcode": 0b0100011, "type": "S", "funct3": 0x1},

         "sw":    {"opcode": 0b0100011, "type": "S", "funct3": 0x2},
         "addi":  {"opcode": 0b0010011, "type": "I", "funct3": 0x0},
         "slti":  {"opcode": 0b0010011, "type": "I", "funct3": 0x2},
         "sltiu": {"opcode": 0b0010011, "type": "I", "funct3": 0x3},
         "xori":  {"opcode": 0b0010011, "type": "I", "funct3": 0x4},
         "ori":   {"opcode": 0b0010011, "type": "I", "funct3": 0x6},
         "andi":  {"opcode": 0b0010011, "type": "I", "funct3": 0x7},
         "slli":  {"opcode": 0b0010011, "type": "I", "funct3": 0x1},
         "srli":  {"opcode": 0b0010011, "type": "I", "funct3": 0x5},
         "srai":  {"opcode": 0b0010011, "type": "I", "funct3": 0x5},

         "add":   {"opcode": 0b0110011, "type": "R", "funct3": 0x0},
         "sub":   {"opcode": 0b0110011, "type": "R", "funct3": 0x0},
         "sll":   {"opcode": 0b0110011, "type": "R", "funct3": 0x1},
         "slt":   {"opcode": 0b0110011, "type": "R", "funct3": 0x2},
         "sltu":  {"opcode": 0b0110011, "type": "R", "funct3": 0x3},
         "xor":   {"opcode": 0b0110011, "type": "R", "funct3": 0x4},
         "srl":   {"opcode": 0b0110011, "type": "R", "funct3": 0x5},
         "sra":   {"opcode": 0b0110011, "type": "R", "funct3": 0x5},
         "or":    {"opcode": 0b0110011, "type": "R", "funct3": 0x6},
         "and":   {"opcode": 0b0110011, "type": "R", "funct3": 0x7}}

# Masks
OPCODE_MASK = 0x7F
U_IMM_MASK = 0xFFFFF000
I_IMM_MASK = 0xFFF00000
RS2_MASK = 0x1F00000
RS1_MASK = 0xF8000
FUNCT3_MASK = 0x7000
FUNCT7_MASK = 0xFE000000
RD_MASK = 0xF80
S_IMM115_MASK = 0xFE000000
S_IMM40_MASK = 0xF80
B_IMM105_MASK = 0x7E000000
B_IMM41_MASK = 0xF00
B_IMM7_MASK = 0x80
J_IMM1912_MASK = 0xFF000
J_IMM11_MASK = 0x100000
J_IMM101_MASK = 0x7FE00000


def find_instr_name(opcode, instr_type, funct3):
    for parent_key, inner_dict in INSTR.items():
        if inner_dict["opcode"] == opcode and inner_dict["type"] == instr_type and inner_dict["funct3"] == funct3:
            return parent_key
    return None  # Return None if no match is found


# Concatenate two binary numbers
def concat(a, b):
    return int(f"{a}{b}")


def instruction_type(opcode):
    if ((opcode == 0x37) or (opcode == 0x17)):  # TODO: check if this needs to be changed
        inst_type = 'U'
    elif opcode == 0x63:
        inst_type = 'B'
    elif opcode == 0x33:
        inst_type = 'R'
    elif opcode == 0x23:
        inst_type = 'S'
    elif ((opcode == 0x13) or (opcode == 0x67) or (opcode == 0x0F)):
        # 0x0F - fence
        inst_type = 'I'
    elif (opcode == 0x6F):
        inst_type = 'J'
    else:
        raise Exception('Unknown type with opcode = '+str(hex(opcode)))
    return inst_type


def u_decoding(inst):
    imm = (inst & U_IMM_MASK) >> 12
    rd = (inst & RD_MASK) >> 7
    opcode = inst & OPCODE_MASK
    return imm, rd, opcode


def i_decoding(inst):
    imm = (inst & I_IMM_MASK) >> 20
    rs1 = (inst & RS1_MASK) >> 15
    funct3 = (inst & FUNCT3_MASK) >> 12
    rd = (inst & RD_MASK) >> 7
    opcode = inst & OPCODE_MASK
    return imm, rs1, funct3, rd, opcode


def r_decoding(inst):
    funct7 = (inst & FUNCT7_MASK) >> 25
    rs2 = (inst & RS2_MASK) >> 20
    rs1 = (inst & RS1_MASK) >> 15
    funct3 = (inst & FUNCT3_MASK) >> 12
    rd = (inst & RD_MASK) >> 7
    opcode = inst & OPCODE_MASK
    return funct7, rs2, rs1, funct3, rd, opcode


def s_decoding(inst):
    imm11 = (inst & S_IMM115_MASK) >> 25
    rs2 = (inst & RS2_MASK) >> 20
    rs1 = (inst & RS1_MASK) >> 15
    funct3 = (inst & FUNCT3_MASK) >> 12
    imm40 = (inst & S_IMM40_MASK) >> 7
    opcode = inst & OPCODE_MASK
    imm = concat(imm11, imm40)
    return imm, rs2, rs1, funct3, opcode


def b_decoding(inst):
    imm12 = inst >> 31
    imm10 = (inst & B_IMM105_MASK) >> 25
    rs2 = (inst & RS2_MASK) >> 20
    rs1 = (inst & RS1_MASK) >> 15
    funct3 = (inst & FUNCT3_MASK) >> 12
    imm4 = (inst & B_IMM41_MASK) >> 8
    imm11 = (inst & B_IMM7_MASK) >> 7
    opcode = inst & OPCODE_MASK
    imm = concat(imm12, concat(imm11, concat(imm10, imm4)))*2
    return imm, rs2, rs1, funct3, opcode


def j_decoding(inst):
    opcode = inst & OPCODE_MASK                 # 6 bits [0-6]
    rd = (inst & RD_MASK) >> 7                  # 5 bits [7-11]
    imm1912 = (inst & J_IMM1912_MASK) >> 12     # 8 bits [12-19]
    imm11 = (inst & J_IMM11_MASK) >> 20         # 1 bit [20]
    imm101 = (inst & J_IMM101_MASK) >> 21       # 10 bits [21-30]
    imm12 = inst >> 31                          # 1 bit [31]
    return imm12, imm101, imm11, imm1912, rd, opcode


def instruction_parsing(inst_type, instruction):
    if inst_type == 'U':
        return u_decoding(instruction)
    elif inst_type == 'I':
        return i_decoding(instruction)
    elif inst_type == 'R':
        return r_decoding(instruction)
    elif inst_type == 'S':
        return s_decoding(instruction)
    elif inst_type == 'B':
        return b_decoding(instruction)
    elif inst_type == 'J':
        return j_decoding(instruction)
    else:
        raise Exception("Not decoded yet")


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


regnames = ["x0", "ra", "sp", "gp", "tp"] + ["t%d" % i for i in range(0, 3)] + ["s0", "s1"] + [
    "a%d" % i for i in range(0, 8)] + ["s%d" % i for i in range(2, 12)] + ["t%d" % i for i in range(3, 7)] + ["PC"]

memory = None
PC = 32


class Regfile:
    def __init__(self):
        self.regs = [0] * 33

    def __getitem__(self, key):  # __X__ enables get/set via []
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
    result = (instr >> e) & ((1 << (s - e + 1)) - 1)
    return result


# Executes a single instruction
def execute(type, instruction_elements):
    if (type == 'U'):
        [imm, rd, opcode] = instruction_elements
    elif (type == 'I'):
        [imm, rs1, funct3, rd, opcode] = instruction_elements
    elif (type == 'R'):
        [funct7, rs2, rs1, funct3, rd, opcode] = instruction_elements
    elif (type == 'S'):
        [imm, rs2, rs1, funct3, opcode] = instruction_elements
    elif (type == 'B'):
        [imm, rs2, rs1, funct3, opcode] = instruction_elements
    elif (type == 'J'):
        [imm12, imm101, imm11, imm1912, rd, opcode] = instruction_elements
        print(bin(imm12), bin(imm101), bin(imm11),
              bin(imm1912), bin(rd), bin(opcode))
    else:
        raise Exception("Not decoded yet")


def process():
    global PC
    regfile[PC] -= 0x80000000
    for i in range(421):
        # *** Fetch ***
        instr = fetch(regfile[PC])
        # *** Decode ***
        op = OP(extractBits(instr, 6, 0))
        if (op != OP.SYSTEM):
            print(hex(instr))
            type = instruction_type(op.value)
            print("{:<4} {:<10} {:<2} {:<2}".format(i, hex(instr), "->", type))
            intruction_elements = instruction_parsing(type, instr)
            execute(type, intruction_elements)

        # move PC
        regfile[PC] += 0x4

    """
    regfile[PC] points to the next instr
        // fetch next instr
        // process
    """
    return False


def main():
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
            while process():
                instrcnt += 1
            print("run %d instructions" % instrcnt)


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
0000000             rs2         rs1         000                 rd              0110011    ADD
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
