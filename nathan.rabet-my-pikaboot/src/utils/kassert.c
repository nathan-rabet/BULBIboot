#include "kassert.h"

#include "asm.h"
#include "kstring.h"
#include "uart.h"

#define STRINGIFY(x) #x

void kassert(int condition)
{
    if (!condition)
        panic("Assertion failed: " STRINGIFY(condition));
}

void panic(const char *msg)
{
    kputs(CRLF "HeeHooHeeHoo !!");

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
