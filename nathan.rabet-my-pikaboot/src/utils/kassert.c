#include "kassert.h"

#include "asm.h"
#include "uart.h"

void kassert(int condition)
{
    if (!condition)
    {
        kputs("Assertion failed!");
        ASM("hlt #0");
    }
}
