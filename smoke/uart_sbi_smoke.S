.section .text.start, "ax"
.globl _start

.equ UART_BASE, 0x10000000
.equ UART_LSR, 5
.equ UART_LSR_THRE, 0x20
.equ SBI_LEGACY_CONSOLE_PUTCHAR, 1
.equ SBI_LEGACY_SHUTDOWN, 8

_start:
  li t0, UART_BASE

  la t1, msg_uart
  jal ra, print_uart

  la t1, msg_sbi
  jal ra, print_sbi

  li a7, SBI_LEGACY_SHUTDOWN
  ecall

1:
  wfi
  j 1b

print_uart:
2:
  lbu t2, 0(t1)
  beqz t2, 3f
4:
  lbu t3, UART_LSR(t0)
  andi t3, t3, UART_LSR_THRE
  beqz t3, 4b
  sb t2, 0(t0)
  addi t1, t1, 1
  j 2b
3:
  ret

print_sbi:
5:
  lbu t2, 0(t1)
  beqz t2, 6f
  mv a0, t2
  li a7, SBI_LEGACY_CONSOLE_PUTCHAR
  ecall
  addi t1, t1, 1
  j 5b
6:
  ret

.section .rodata
msg_uart:
  .asciz "[UART] smoke says hello\n"
msg_sbi:
  .asciz "[SBI ] smoke says hello\n"
