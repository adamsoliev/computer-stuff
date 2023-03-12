#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import glob
import subprocess
from enum import Enum
import struct


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


class FUNCT3(Enum):
    JALR = 0b000

    BEQ = 0b000
    BNE = 0b001
    BLT = 0b100
    BGE = 0b101
    BLTU = 0b110
    BGEU = 0b111

    LB = 0b000
    LH = 0b001
    LW = 0b010
    LBU = 0b100
    LHU = 0b101

    SB = 0b000
    SH = 0b001
    SW = 0b010

    # OP-IMM
    ADDI = 0b000
    SLTI = 0b010
    SLTIU = 0b011

    XORI = 0b100
    ORI = 0b110
    ANDI = 0b111

    SLLI = 0b001
    SRLI = 0b101
    SRAI = 0b101

    # OP
    ADD = 0b000
    SUB = 0b000
    SLL = 0b001
    SLT = 0b010
    SLTU = 0b011
    XOR = 0b100
    SRL = 0b101
    SRA = 0b101
    OR = 0b110
    AND = 0b111

    FENCE = 0b000
    ECALL = 0b000
    EBREAK = 0b000
    MRAT = 0b000

    CSRRW = 0b001
    CSRRS = 0b010
    CSRRC = 0b011
    CSRRWI = 0b101
    CSRRSI = 0b110
    CSRRCI = 0b111


regnames = ["x0", "ra", "sp", "gp", "tp"] + ["t%d" % i for i in range(0, 3)] + ["s0", "s1"] + [
    "a%d" % i for i in range(0, 8)] + ["s%d" % i for i in range(2, 12)] + ["t%d" % i for i in range(3, 7)] + ["PC"]

memory = None
PC = 32


class Regfile:
    def __init__(self):
        self.regs = [0] * 33

    def __getitem__(self, key):
        return self.regs[key]

    def __setitem__(self, key, value):
        if (key == 0):
            return
        self.regs[key] = value & 0xFFFFFFFF


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
    addr -= 0x80000000
    if (addr < 0 and addr <= len(memory)):
        raise Exception("read out of bounds: 0x%x" % addr)
    return struct.unpack("<I", memory[addr:addr + 4])[0]


def sign_extend(x, length):
    # unsigned to signed
    if x >> (length-1) == 1:
        return -((1 << length) - x)
    return x


def dump():
    pp = []
    for i in range(33):
        if i != 0 and i % 8 == 0:
            pp += "\n"
        pp += " %3s: %08x" % (regnames[i], regfile[i])
    print(''.join(pp))


def process():
    # fetch
    instruction = fetch(regfile[PC])
    if (instruction == 0):
        return False

    # decode
    # execute
    # write-back
    opcode = OP(extractBits(instruction, 6, 0))

    if (opcode == OP.JAL):
        # J-type instruction
        imm = extractBits(instruction, 32, 31) << 20 | extractBits(instruction, 30, 21) << 1 | extractBits(
            instruction, 21, 20) << 11 | extractBits(instruction, 19, 12) << 12
        offset = sign_extend(imm, 21)
        regfile[PC] += offset

    elif (opcode == OP.OP_IMM):
        # I-type or R-type
        rd = extractBits(instruction, 11, 7)
        funct3 = FUNCT3(extractBits(instruction, 14, 12))
        rs1 = extractBits(instruction, 19, 15)
        imm = extractBits(instruction, 31, 20)
        funct7 = extractBits(instruction, 31, 25)
        value = sign_extend(imm, 12)
        if (funct3 == FUNCT3.ADDI):
            regfile[rd] = regfile[rs1] + value
        elif (funct3 == FUNCT3.SLTI):
            # treat as signed numbers
            # if (sign_extend(regfile[rs1], 32) < value):
            #     regfile[rd] = 1
            # else:
            #     regfile[rd] = 0
            print("slti")
        elif (funct3 == FUNCT3.SLTIU):
            # treat as unsigned numbers
            # if ((regfile[rs1] & 0xFFFFFFFF) < (imm & 0xFFFFFFFF)):
            #     regfile[rd] = 1
            # else:
            #     regfile[rd] = 0
            print("sltiu")
        elif (funct3 == FUNCT3.ANDI):
            regfile[rd] = regfile[rs1] & value
        elif (funct3 == FUNCT3.ORI):
            regfile[rd] = regfile[rs1] | value
        elif (funct3 == FUNCT3.XORI):
            regfile[rd] = regfile[rs1] ^ value
        elif (funct3 == FUNCT3.SLLI and funct7 == 0b0000000):
            shamt = extractBits(instruction, 24, 20)
            regfile[rd] = regfile[rs1] << shamt
        elif (funct3 == FUNCT3.SRLI and funct7 == 0b0000000):
            # zero extend (logical right shift)
            shamt = extractBits(instruction, 24, 20)
            regfile[rd] = regfile[rs1] >> shamt
        elif (funct3 == FUNCT3.SRAI and funct7 == 0b0100000):
            shamt = extractBits(instruction, 24, 20)
            # sign-extend (arithmetic right shift)
            sb = regfile[rs1] >> 31
            regfile[rd] = regfile[rs1] >> shamt
            regfile[rd] |= (0xffffffff * sb) << (32 - shamt)
        else:
            raise Exception("write funct3 %r" % funct3)

    elif (opcode == OP.OP):
        rd = extractBits(instruction, 11, 7)
        funct3 = FUNCT3(extractBits(instruction, 14, 12))
        rs1 = extractBits(instruction, 19, 15)
        rs2 = extractBits(instruction, 24, 20)
        funct7 = extractBits(instruction, 31, 25)
        if (funct3 == FUNCT3.ADD and funct7 == 0b0000000):
            regfile[rd] = regfile[rs1] + regfile[rs2]
        elif (funct3 == FUNCT3.SLT and funct7 == 0b0000000):
            if (sign_extend(regfile[rs1]) < sign_extend(regfile[rs2])):
                regfile[rd] = 1
            else:
                regfile[rd] = 0
            print("slt")
        elif (funct3 == FUNCT3.SLTU and funct7 == 0b0000000):
            if (regfile[rs1] < regfile[rs2]):
                regfile[rd] = 1
            else:
                regfile[rd] = 0
        elif (funct3 == FUNCT3.AND and funct7 == 0b0000000):
            print("and")
        elif (funct3 == FUNCT3.OR and funct7 == 0b0000000):
            print("or")
        elif (funct3 == FUNCT3.XOR and funct7 == 0b0000000):
            print("xor")
        elif (funct3 == FUNCT3.SLL and funct7 == 0b0000000):
            print("sll")
        elif (funct3 == FUNCT3.SRL and funct7 == 0b0000000):
            print("srl")
        elif (funct3 == FUNCT3.SUB and funct7 == 0b0100000):
            print("sub")
        elif (funct3 == FUNCT3.SRA and funct7 == 0b0100000):
            print("sra")
        else:
            raise Exception("write %r %r %r" % (opcode, funct3, hex(funct12)))

    elif (opcode == OP.SYSTEM):
        rd = extractBits(instruction, 11, 7)
        funct3 = FUNCT3(extractBits(instruction, 14, 12))
        rs1 = extractBits(instruction, 19, 15)
        funct12 = extractBits(instruction, 31, 20)
        trap_ret = extractBits(instruction, 31, 25)
        if (funct3 == FUNCT3.ECALL and funct12 == 0x0):
            if (regfile[3] > 1):
                print("     ecall", regfile[3])
                raise Exception("Test failed")
        elif (funct3 == FUNCT3.EBREAK and funct12 == 0x1):
            print("ebreak")
        elif (funct3 == FUNCT3.CSRRW):
            print("csrrw")
        elif (funct3 == FUNCT3.CSRRS):
            print("csrrs")
        elif (funct3 == FUNCT3.CSRRC):
            print("csrrc")
        elif (funct3 == FUNCT3.CSRRWI):
            print("csrrwi")
        elif (funct3 == FUNCT3.CSRRSI):
            print("csrrsi")
        elif (funct3 == FUNCT3.CSRRCI):
            print("csrrci")
        elif (funct3 == FUNCT3.MRAT and trap_ret == 0b0011000):
            # TODO: could be handled differently in an actual system
            print("mrat")
            pass
        else:
            raise Exception("write %r %r %r" % (opcode, funct3, hex(funct12)))

    elif (opcode == OP.BRANCH):
        funct3 = FUNCT3(extractBits(instruction, 14, 12))
        rs1 = extractBits(instruction, 19, 15)
        rs2 = extractBits(instruction, 24, 20)
        imm = extractBits(
            instruction, 32, 31) << 12 | extractBits(instruction, 30, 25) << 5 | extractBits(instruction, 11, 8) << 1 | extractBits(instruction, 8, 7) << 11
        offset = sign_extend(imm, 13)
        cond = False
        if (funct3 == FUNCT3.BEQ):
            cond = regfile[rs1] == regfile[rs2]
        elif (funct3 == FUNCT3.BNE):
            cond = regfile[rs1] != regfile[rs2]
        elif (funct3 == FUNCT3.BLT):
            cond = sign_extend(regfile[rs1], 32) < sign_extend(
                regfile[rs2], 32)
        elif (funct3 == FUNCT3.BGE):
            print("bge")
        elif (funct3 == FUNCT3.BLTU):
            cond = regfile[rs1] < regfile[rs2]
        elif (funct3 == FUNCT3.BGEU):
            print("bgeu")
        else:
            raise Exception("write funct3 %r" % funct3)
        if (cond):
            regfile[PC] += offset
            return True

    elif (opcode == OP.AUIPC):
        # U-type instruction
        rd = extractBits(instruction, 11, 7)
        imm = extractBits(instruction, 31, 12)
        offset = imm << 12
        regfile[rd] = regfile[PC] + offset

    elif (opcode == OP.LUI):
        # U-type instruction
        rd = extractBits(instruction, 11, 7)
        imm = extractBits(instruction, 31, 12)
        constant = imm << 12
        regfile[rd] = constant

    elif (opcode == OP.MISC_MEM):
        print("misc-mem")
    elif (opcode == OP.LOAD):
        # I-type instruction
        rd = extractBits(instruction, 11, 7)
        funct3 = FUNCT3(extractBits(instruction, 14, 12))
        rs1 = extractBits(instruction, 19, 15)
        imm = extractBits(instruction, 31, 20)
        value = sign_extend(imm, 12)
        addr = regfile[rs1] + value
        # value = sign_extend(imm, 12)
        if (funct3 == FUNCT3.LB):
            regfile[rd] = sign_extend(fetch(addr) & 0xff, 8)
        elif (funct3 == FUNCT3.LBU):
            regfile[rd] = fetch(addr) & 0xff
        elif (funct3 == FUNCT3.LH):
            regfile[rd] = sign_extend(fetch(addr) & 0xffff, 16)
        elif (funct3 == FUNCT3.LHU):
            regfile[rd] = fetch(addr) & 0xffff
        elif (funct3 == FUNCT3.LW):
            regfile[rd] = fetch(addr)
        else:
            raise Exception("write funct3 %r" % funct3)
    elif (opcode == OP.STORE):
        print("store")
    else:
        dump()
        raise Exception("write opcode %r" % opcode)

    print("{:<12} {:<12} {:<10}".format(
        hex(regfile[PC]), hex(instruction), opcode))

    # dump()
    regfile[PC] += 0x4
    return True


def extractBits(instruction, start, end):
    return (instruction >> end) & ((1 << (start-end+1))-1)


def main():
    for x in glob.glob("/home/adam/dev/riscv-tests/isa/rv32ui-p-lb"):
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
            regfile[PC] = 0x80000000
            instrcnt = 0

            while process():
                instrcnt += 1
            print("run %d instructions" % instrcnt)


if __name__ == '__main__':
    main()
