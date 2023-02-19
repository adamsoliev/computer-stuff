#include <iostream>
#include <bitset>
#include <verilated.h>
#include "VALU8.h"

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);

    VALU8 *alu = new VALU8;

    alu->A = 0x64;
    alu->B = 0x18;

    alu->opcode = 0; // addition
    alu->eval();

    std::cout << "A + B = " << std::bitset<8>(alu->result) << std::endl;
    if (alu->result != 0x7C) {
        std::cerr << "Addition test failed!" << std::endl;
        return 1;
    }

    alu->opcode = 1; // subtraction
    alu->eval();
    std::cout << "A - B = " << std::bitset<8>(alu->result) << std::endl;
    if (alu->result != 0x4C) {
        std::cerr << "Subtraction test failed!" << std::endl;
        return 1;
    }

    alu->opcode = 2; // multiplication
    alu->eval();
    // overflow multiplication
    std::cout << "A * B = " << std::bitset<8>(alu->result) << std::endl;
    if (alu->result != 0x60) {
        std::cerr << "Multiplication test failed!" << std::endl;
        return 1;
    }
    // normal multiplication
    alu->A = 0x9;
    alu->B = 0xF;
    alu->eval();
    std::cout << "A * B = " << std::bitset<8>(alu->result) << std::endl;
    if (alu->result != 0x87) {
        std::cerr << "Multiplication test failed!" << std::endl;
        return 1;
    }

    alu->opcode = 3; // division
    alu->A = 0xC0;
    alu->B = 0x8;
    alu->eval();
    // normal division
    std::cout << "A / B = " << std::bitset<8>(alu->result) << std::endl;
    if (alu->result != 0x18) {
        std::cerr << "Division test failed!" << std::endl;
        return 1;
    }
    // division by zero
    alu->A = 0xC0;
    alu->B = 0x0;
    alu->eval();
    std::cout << "A / B = " << std::bitset<8>(alu->result) << std::endl;
    if (alu->result != 0xFF) {
        std::cerr << "Division test failed!" << std::endl;
        return 1;
    }

    std::cout << "All tests passed!" << std::endl;

    delete alu;
    return 0;
}