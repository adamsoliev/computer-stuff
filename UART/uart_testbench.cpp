#include <iostream>
#include <verilated.h>
#include <bitset>
#include "Vuart.h"

int main(int argc, char **argv) {

    Verilated::commandArgs(argc, argv);

    Vuart *uart = new Vuart;

    // set initial state
    uart->clk = 0;
    uart->eval();
    uart->clk = 1;
    uart->rst = 1;
    uart->eval();

    uart->in_data = 199;

    uart->rst = 0;

    for (int i = 0; i < 20; i++) {
        // ================
        uart->clk = 0;
        uart->eval();
        uart->clk = 1;
        uart->eval();
        // std::cout << "i: " << i << std::endl;
        // std::cout << "txd: " << std::bitset<8>(uart->txd) << std::endl;
        // std::cout << "rxd: " << std::bitset<8>(uart->rxd) << std::endl;
        // std::cout << std::endl;
        // ================
    }
    std::cout << std::bitset<8>(uart->in_data) << std::endl;
    std::cout << std::bitset<8>(uart->out_data) << std::endl;

    // Clean up
    uart->final();
    delete uart;

    return 0;
}