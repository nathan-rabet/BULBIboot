.section ".text.startup"

.global _start
_start:
    // Create a stack frame
    ldr x30, =STACK_TOP
    mov sp, x30

    // Call kmain function
    bl kmain

.halt:
    hlt #0
