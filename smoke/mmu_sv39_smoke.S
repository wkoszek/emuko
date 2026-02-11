.section .text.start, "ax"
.globl _start

.equ SBI_LEGACY_CONSOLE_PUTCHAR, 1
.equ SBI_LEGACY_SHUTDOWN, 8

.equ PTE_V, 0x001
.equ PTE_R, 0x002
.equ PTE_W, 0x004
.equ PTE_X, 0x008
.equ PTE_A, 0x040
.equ PTE_D, 0x080

_start:
  li sp, 0x80100000

  la t0, trap_handler
  csrw stvec, t0

  # Clear root page table.
  la t0, root_pt
  li t1, 0
  li t2, 512
1:
  sd t1, 0(t0)
  addi t0, t0, 8
  addi t2, t2, -1
  bnez t2, 1b

  # 1GiB leaf mapping to physical 0x80000000 with RWXAD.
  li t3, 0x80000              # PPN for 0x80000000
  slli t3, t3, 10
  li t4, (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)
  or t3, t3, t4

  # Identity map: VPN2=2 -> 0x80000000..0xbfffffff.
  la t0, root_pt
  li t1, 2
  slli t1, t1, 3
  add t0, t0, t1
  sd t3, 0(t0)

  # High-half alias: VPN2=510 -> virtual 0xffffffff80000000..0xffffffffbfffffff.
  la t0, root_pt
  li t1, 510
  slli t1, t1, 3
  add t0, t0, t1
  sd t3, 0(t0)

  # Enable Sv39.
  la t0, root_pt
  srli t0, t0, 12
  li t1, 8
  slli t1, t1, 60
  or t0, t0, t1
  csrw satp, t0
  sfence.vma zero, zero

  la a0, msg_mmu_on
  jal ra, puts

  # Precompute pointers that high-half code will use.
  la s1, msg_high
  la s2, msg_ok
  la s3, msg_fail
  la s4, test_data
  li t1, 0xffffffff80000000
  li t2, 0x80000000
  sub s4, s4, t2
  add s4, s4, t1

  # Jump to a high virtual alias of high_mode_start.
  la t0, high_mode_start
  li t1, 0xffffffff80000000
  li t2, 0x80000000
  sub t0, t0, t2
  add t0, t0, t1
  jr t0

high_mode_start:
  mv a0, s1
  jal ra, puts

  # Store+load through high virtual alias.
  mv t0, s4
  li t3, 0x12345
  sd t3, 0(t0)
  ld t4, 0(t0)
  bne t3, t4, fail

  # Trigger load page fault on an unmapped address.
  li t0, 0x40000000
  ld t1, 0(t0)

after_page_fault:
  mv a0, s2
  jal ra, puts
  li a7, SBI_LEGACY_SHUTDOWN
  ecall

spin:
  wfi
  j spin

.align 2
trap_handler:
  csrr t0, scause
  li t1, 13                     # Load page fault.
  bne t0, t1, fail
  csrr t2, sepc
  addi t2, t2, 4                # Skip faulting LD.
  csrw sepc, t2
  sret

puts:
  mv t5, a0
2:
  lbu t6, 0(t5)
  beqz t6, 3f
  mv a0, t6
  li a7, SBI_LEGACY_CONSOLE_PUTCHAR
  ecall
  addi t5, t5, 1
  j 2b
3:
  ret

fail:
  mv a0, s3
  jal ra, puts
  li a7, SBI_LEGACY_SHUTDOWN
  ecall
  j fail

.section .rodata
msg_mmu_on:
  .asciz "[MMU ] satp=sv39 enabled\n"
msg_high:
  .asciz "[MMU ] high VA fetch/load/store ok\n"
msg_ok:
  .asciz "[MMU ] page-fault trap path ok\n"
msg_fail:
  .asciz "[MMU ] FAIL\n"

.section .bss
.align 12
root_pt:
  .space 4096
.align 3
test_data:
  .dword 0
