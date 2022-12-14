.global _ _down_to_el1

_down_el:
    mrs x0, CurrentEL
    cmp x0, #0b1000  // remember the EL value is stored in bits 2 and 3
    beq in_el2
    blo in_el1

in_el3:
    // Put code switching from EL3 to EL2 here

in_el2:
    // This code will run at EL2

in_el1:
    // We are in EL0 or EL1, so we probably should report an error here

