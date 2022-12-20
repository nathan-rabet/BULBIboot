#include "kassert.h"

#include "asm.h"
#include "kstring.h"
#include "uart.h"

#define STRINGIFY(x) #x

void kassert(bool condition)
{
    if (!condition)
        panic("Assertion failed at " __FILE__ ":" STRINGIFY(__LINE__));
}

void kassertm(bool condition, const char *msg)
{
    if (!condition)
        panic(msg);
}

void panic(const char *msg)
{
    kputs(CRLF "HeeHooHeeHoo !!" CRLF);

    kputs("██████   █████  ███    ██ ██  ██████ " CRLF);
    kputs("██   ██ ██   ██ ████   ██ ██ ██      " CRLF);
    kputs("██████  ███████ ██ ██  ██ ██ ██      " CRLF);
    kputs("██      ██   ██ ██  ██ ██ ██ ██      " CRLF);
    kputs("██      ██   ██ ██   ████ ██  ██████ " CRLF);
    kputs("                                     " CRLF CRLF);

    kputs(msg);
    kputs(CRLF);
    ASM("hlt #0");
}
