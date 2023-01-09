
.global _linux_boot

_linux_boot:

    //
    // FUNCTION CALL PARAMETERS
    // ------------------------
    // x0 = dtb
    // x1 = kernel address
    // ------------------------

    //
    // LINUX KERNEL REQUIREMENTS
    // -------------------------
    // x0: Device tree blob
    // x1: 0 (reserved)
    // x2: 0 (reserved)
    // x3: 0 (reserved)
    // -------------------------
    

    mov x4, x0 // Save dtb in x4
    mov x5, x1 // Save kernel address in x5

    bl _down_el1 // Call _down_el1

_down_el1:
    mrs x0, CurrentEL // get the current EL
    cmp x0, #0b1000  // remember the EL value is stored in bits 2 and 3
    beq _in_el2 // if we are in EL2, jump to the _in_el2 label
    blo _in_el1 // if we are in EL1, jump to the _in_el1 label

_in_el3:
    // Will run in EL3
    adr x0, _in_el2 // get the address of the _in_el2 label
    msr ELR_EL3, x0 // set the ELR_EL3 register to the address of the _in_el2 label
    
    mov x0, xzr // clear x0
    mov x0, #0b01001
    msr SPSR_EL3, x0 // set the SPSR_EL3 register to 9

    eret // return to EL2

_in_el2:
    // Will run in EL2
    // Same as _in_el3, but with EL2 instead of EL3
    adr x0, _in_el1
    msr ELR_EL2, x0

    mov x0, xzr
    mov x0, #0b01001
    msr SPSR_EL2, x0

    eret

_in_el1:
    // Will run in EL1
    
    // LINUX BOOT
    
    mov x0, x4 // Move dtb to x0

    // Set x1, x2, x3 to 0;
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr

    // Jump to kernel
    br x5

