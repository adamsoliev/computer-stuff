#include <verilated.h>
#include <verilated_vcd_c.h>
#include "Vimpl_top.h"

#include <iostream>

#define CLOCK_PERIOD 10 // in nanoseconds

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);
    Vimpl_top *top = new Vimpl_top;

    // Enable waveform tracing
    Verilated::traceEverOn(true);
    VerilatedVcdC* trace = new VerilatedVcdC;
    top->trace(trace, 99);
    trace->open("impl_top.vcd");

    // Set inputs
    top->clk = 0;
    top->sw_0 = 1;
    top->sw_1 = 0;
    top->uart_rxd = 0;

    // Simulate for 100 clock cycles
    for (int i = 0; i < 100; i++) {
        // Toggle clock
        top->clk = !top->clk;

        // Evaluate inputs
        top->eval();

        // Dump waveform
        trace->dump(10*i);

        // Check UART output
        if (top->uart_tx_en && !top->uart_tx_busy) {
            std::cout << top->uart_tx_data << std::endl;
        }

        // Set UART input
        if (i == 10) {
            top->uart_rxd = 0x48; // 'H'
        } else if (i == 20) {
            top->uart_rxd = 0x65; // 'e'
        } else if (i == 30) {
            top->uart_rxd = 0x6c; // 'l'
        } else if (i == 40) {
            top->uart_rxd = 0x6c; // 'l'
        } else if (i == 50) {
            top->uart_rxd = 0x6f; // 'o'
        } else if (i == 60) {
            top->uart_rxd = 0x20; // ' '
        } else if (i == 70) {
            top->uart_rxd = 0x57; // 'W'
        } else if (i == 80) {
            top->uart_rxd = 0x6f; // 'o'
        } else if (i == 90) {
            top->uart_rxd = 0x72; // 'r'
        }

        // Wait for clock period
        if (top->clk) {
            sc_time_stamp() += CLOCK_PERIOD/2;
        }
    }

    trace->close();
    top->final();

    delete top;
    delete trace;

    return 0;
}
