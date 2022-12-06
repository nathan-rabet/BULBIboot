
.global linux_boot

linux_boot:

    //
    // FUNCTION CALL PARAMETERS
    // ------------------------
    // x0 = dtb
    // x1 = QEMU kmain offset
    // ------------------------

    //
    // LINUX KERNEL REQUIREMENTS
    // -------------------------
    // x0: Device tree blob
    // x1: 0 (reserved)
    // x2: 0 (reserved)
    // x3: 0 (reserved)
    // -------------------------
    

    // x4 = x1 + 50 MiB
    mov x4, x1
    mov x5, 0x3200000
    add x4, x4, x5

    // Set x1, x2, x3 to 0;
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr

    // Jump to kernel
    br x4
