/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_ARM_H
#define UC_QEMU_TARGET_ARM_H

// functions to read & write registers
int arm_reg_read(struct qc_struct *uc, unsigned int *regs, void **vals,
                 int count);
int arm_reg_write(struct qc_struct *uc, unsigned int *regs, void *const *vals,
                  int count);
int arm64_reg_read(struct qc_struct *uc, unsigned int *regs, void **vals,
                   int count);
int arm64_reg_write(struct qc_struct *uc, unsigned int *regs, void *const *vals,
                    int count);

int arm_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                         void **vals, int count);
int arm_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                          void *const *vals, int count);
int armeb_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count);
int armeb_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count);
int arm64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count);
int arm64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count);
int arm64eb_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count);
int arm64eb_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count);

void arm_reg_reset(struct qc_struct *uc);
void arm64_reg_reset(struct qc_struct *uc);

void arm_qc_init(struct qc_struct *uc);
void armeb_qc_init(struct qc_struct *uc);

void arm64_qc_init(struct qc_struct *uc);
void arm64eb_qc_init(struct qc_struct *uc);
#endif
