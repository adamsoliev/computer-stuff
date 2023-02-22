#include <iostream>
#include <verilated.h>
#include <bitset>
#include "Vuart.h"

int main(int argc, char **argv) {

    Verilated::commandArgs(argc, argv);

    Vuart *uart = new Vuart;

    // set initial state
    uart->clk = 0;
    uart->rst = 1;
    uart->eval();
    uart->in_data = 147;

    // wait for a fiew clk cycles
    uart->rst = 0;

    for (int i = 0; i < 30; i++) {
        // ================
        uart->clk = 0;
        uart->eval();
        uart->clk = 1;
        uart->eval();
        // ================
    }
    std::cout << std::bitset<8>(uart->in_data) << std::endl;
    std::cout << std::bitset<8>(uart->out_data) << std::endl;

    // Clean up
    uart->final();
    delete uart;

    return 0;
}