#ifndef UART_H
#define UART_H

#include <stdint.h>

void kputc(char c);

char kgetc();

void kputs(const char *s);

#endif /* UART_H */
