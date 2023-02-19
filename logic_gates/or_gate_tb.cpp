#include <verilated.h>
#include "Vor_gate.h"

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);

    Vor_gate* top = new Vor_gate;

    top->a = 0;
    top->b = 0;
    top->eval();
    printf("a = %d, b = %d, y = %d\n", top->a, top->b, top->y);

    top->a = 1;
    top->b = 0;
    top->eval();
    printf("a = %d, b = %d, y = %d\n", top->a, top->b, top->y);

    top->a = 0;
    top->b = 1;
    top->eval();
    printf("a = %d, b = %d, y = %d\n", top->a, top->b, top->y);

    top->a = 1;
    top->b = 1;
    top->eval();
    printf("a = %d, b = %d, y = %d\n", top->a, top->b, top->y);

    delete top;

    return 0;
}