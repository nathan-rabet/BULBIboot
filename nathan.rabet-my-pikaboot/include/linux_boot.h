#ifndef LINUX_BOOT_H
#define LINUX_BOOT_H

#ifndef KERNEL_IMG_LEN
#    define KERNEL_IMG_LEN 0
#    error "KERNEL_IMG_LEN must be defined"
#endif

#ifndef KERNEL_CRC
#    define KERNEL_CRC 0
#    error "KERNEL_CRC must be defined"
#endif

#include "int.h"

/**
 * @brief Boot a linux kernel
 *
 * @note The kernel address and the device tree blob address must be set before
 * using the functions linux_set_kernel_addr() and linux_set_dtb().
 * If they are not set, the function will panic.
 */
void linux_boot();

/**
 * @brief Get the device tree blob address
 *
 * @return void* The address of the device tree blob
 */
volatile const void *linux_get_dtb_addr(void);

/**
 * @brief Get the kernel address
 *
 * @return void* The address of the kernel
 */
volatile void *linux_get_kernel_addr(void);

/**
 * @brief Set the kernel address
 *
 * @param kernel_addr The address of the kernel
 */
void linux_set_kernel_addr(volatile void *kernel_addr);

/**
 * @brief Set the device tree blob address
 *
 * @param dtb The address of the device tree blob
 */
void linux_set_dtb_addr(volatile void *dtb);

#endif /* LINUX_BOOT_H */
