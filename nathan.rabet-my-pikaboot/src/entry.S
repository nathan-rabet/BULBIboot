.section ".text.startup"

.global _start
_start:
    // Create a stack frame
    ldr x30, =STACK_TOP
    mov sp, x30

    // Call bmain function
    bl bmain

.hang:
    b .hang

