
.global _linux_boot

_linux_boot:

    //
    // FUNCTION CALL PARAMETERS
    // ------------------------
    // x0 = dtb
    // x1 = kernel entry point
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

    // Set x1, x2, x3 to 0;
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr

    // Jump to kernel
    br x4
