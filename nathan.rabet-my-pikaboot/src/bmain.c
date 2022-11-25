#include "asm.h"
#include <stdint.h>

void bmain(void) {
  uint64_t a = 0x1234567890ABCDEF;
  uint64_t b = 0x1234567890ABCDEF;

  // ARM AArch64 assembly : put a in register x0, b in register x1
  ASM("" : : "r"(a), "r"(b));
  // ARM AArch64 assembly : add x0 and x1, and put the result in x0
  ASM("add x0, x0, x1");
  // ARM AArch64 assembly : put x0 in a
  ASM("" : "=r"(a) :);

  // Now a contains 0x2468ACF13579BDFE
  while (1)
    ;
}
