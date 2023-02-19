#include <iostream>
#include <bitset>
#include <verilated.h>
#include "VALU8.h"

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);

    VALU8 *alu = new VALU8;

    alu->A = 0x64;
    alu->B = 0x18;
    alu->opcode = 0;

    for (int i = 0; i < 10; i++) {
        alu->eval();

        // std::cout << std::bitset<8>(alu->A) << std::endl;
        // std::cout << std::bitset<8>(alu->B) << std::endl;

        std::cout << "A + B = " << std::bitset<8>(alu->result) << std::endl;
        if (alu->result != (alu->A + alu->B)) {
            std::cerr << "Test failed!" << std::endl;
            return 1;
        }

        alu->opcode = 1;
        alu->eval();
        std::cout << "A - B = " << std::bitset<8>(alu->result) << std::endl;
        if (alu->result != (alu->A - alu->B)) {
            std::cerr << "Test failed!" << std::endl;
            return 1;
        }

        alu->A += 1;
        alu->B += 2;
        alu->opcode = 0;
    }

    std::cout << "All tests passed!" << std::endl;

    delete alu;
    return 0;
}