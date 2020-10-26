/**
 * @file secmain.S
 * @brief Override secondary_main
 * @details This run all test group
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

.section .text.start
.global secondary_main
.type   secondary_main, @function

/*
 * Overload default secondary_main function to load command line from a QEMU
 * VM command line if any.
 *
 * load_cmdline C function updates a0 with argc and a1 with argv.
 */
secondary_main:
  addi sp, sp, -16
#if __riscv_xlen == 32
  sw ra, 4(sp)
#else
  sd ra, 8(sp)
#endif
  csrr t0, mhartid
  la t1, __metal_boot_hart
  beq t0, t1, 2f
1:
  wfi
  j 1b
2:
  call load_cmdline
  call main
#if __riscv_xlen == 32
  lw ra, 4(sp)
#else
  ld ra, 8(sp)
#endif
  addi sp, sp, 16
  ret
