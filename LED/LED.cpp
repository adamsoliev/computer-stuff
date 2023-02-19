#include "VLED.h"
#include <iostream>
#include <verilated.h>

int main(int argc, char **argv) {

    Verilated::commandArgs(argc, argv);

    VLED *led = new VLED;

    // set initial state
    led->clock = 0;
    led->reset = 1;
    led->eval();

    // wait for a fiew clock cycles
    led->reset = 0;

    for (int i = 0; i < 30; i++) {
        // ================
        led->clock = 0;
        led->eval();
        led->clock = 1;
        led->eval();
        // ================
        printf("LED value: %d\n", led->led);
    }

    // Clean up
    led->final();
    delete led;

    return 0;
}
