.section ".text.startup"

.global _start

.macro init_vfpu
    mov x1, #(0x3 << 20)
    msr cpacr_el1, x1
    isb
.endm /* init_vfpu */

_start:
    // Create a stack frame
    ldr x30, =STACK_TOP
    mov sp, x30

    // Initialize the VFPU (macro)
    init_vfpu
    
    // Call kmain function
    bl kmain

.halt:
    hlt #0
