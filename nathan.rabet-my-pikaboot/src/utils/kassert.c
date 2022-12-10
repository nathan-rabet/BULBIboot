#include "kassert.h"

#include "asm.h"
#include "kstring.h"
#include "uart.h"

void kassert(int condition)
{
    if (!condition)
    {
        kputs("Assertion failed!");
        ASM("hlt #0");
    }
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
