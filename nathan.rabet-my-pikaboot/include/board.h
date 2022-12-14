#ifndef BOARD_H
#define BOARD_H

#if defined(VIRT_BOARD)
#    include "virt.h"
#    define UART0_BOARD_ADDR UART0_ADDR
#    define RAM_START_BOARD RAM_START

#elif defined(ORANGEPI_BOARD)
#    include "orangepi_pc.h"
#    define UART0_BOARD_ADDR AW_H3_DEV_UART0
#    define RAM_START_BOARD AW_H3_DEV_SDRAM
#elif defined(VEXPRESS_A15_BOARD)
#    include "vexpress_a15.h"
#    define UART0_BOARD_ADDR VE_UART0
#    define RAM_START_BOARD VE_SRAM
#endif
#endif /* BOARD_H */
