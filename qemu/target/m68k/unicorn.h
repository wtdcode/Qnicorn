/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_M68K_H
#define UC_QEMU_TARGET_M68K_H

// functions to read & write registers
int m68k_reg_read(struct qc_struct *uc, unsigned int *regs, void **vals,
                  int count);
int m68k_reg_write(struct qc_struct *uc, unsigned int *regs, void *const *vals,
                   int count);
int m68k_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count);
int m68k_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count);

void m68k_reg_reset(struct qc_struct *uc);

void m68k_qc_init(struct qc_struct *uc);
#endif
