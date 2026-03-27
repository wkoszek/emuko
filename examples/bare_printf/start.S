/* start.S — bare-metal RISC-V entry point */
        .section .text.entry
        .global  _start
_start:
        /* Set up the stack */
        la      sp, _stack_top

        /* Zero the BSS section */
        la      a0, _bss_start
        la      a1, _bss_end
.Lbss:
        bgeu    a0, a1, .Lbss_done
        sd      zero, 0(a0)
        addi    a0, a0, 8
        j       .Lbss
.Lbss_done:

        call    main

        /* main() should never return; spin if it does */
.Lhalt:
        j       .Lhalt
