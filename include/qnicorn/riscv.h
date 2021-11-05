/* Unicorn Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2020 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
 */

#ifndef QNICORN_RISCV_H
#define QNICORN_RISCV_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

//> RISCV32 CPU
typedef enum qc_cpu_riscv32 {
    QC_CPU_RISCV32_ANY = 0,
    QC_CPU_RISCV32_BASE32,
    QC_CPU_RISCV32_SIFIVE_E31,
    QC_CPU_RISCV32_SIFIVE_U34,
} qc_cpu_riscv32;

//> RISCV64 CPU
typedef enum qc_cpu_riscv64 {
    QC_CPU_RISCV64_ANY = 0,
    QC_CPU_RISCV64_BASE64,
    QC_CPU_RISCV64_SIFIVE_E51,
    QC_CPU_RISCV64_SIFIVE_U54,
} qc_cpu_riscv64;

//> RISCV registers
typedef enum qc_riscv_reg {
    QC_RISCV_REG_INVALID = 0,
    //> General purpose registers
    QC_RISCV_REG_X0,
    QC_RISCV_REG_X1,
    QC_RISCV_REG_X2,
    QC_RISCV_REG_X3,
    QC_RISCV_REG_X4,
    QC_RISCV_REG_X5,
    QC_RISCV_REG_X6,
    QC_RISCV_REG_X7,
    QC_RISCV_REG_X8,
    QC_RISCV_REG_X9,
    QC_RISCV_REG_X10,
    QC_RISCV_REG_X11,
    QC_RISCV_REG_X12,
    QC_RISCV_REG_X13,
    QC_RISCV_REG_X14,
    QC_RISCV_REG_X15,
    QC_RISCV_REG_X16,
    QC_RISCV_REG_X17,
    QC_RISCV_REG_X18,
    QC_RISCV_REG_X19,
    QC_RISCV_REG_X20,
    QC_RISCV_REG_X21,
    QC_RISCV_REG_X22,
    QC_RISCV_REG_X23,
    QC_RISCV_REG_X24,
    QC_RISCV_REG_X25,
    QC_RISCV_REG_X26,
    QC_RISCV_REG_X27,
    QC_RISCV_REG_X28,
    QC_RISCV_REG_X29,
    QC_RISCV_REG_X30,
    QC_RISCV_REG_X31,

    //> Floating-point registers
    QC_RISCV_REG_F0,  // "ft0"
    QC_RISCV_REG_F1,  // "ft1"
    QC_RISCV_REG_F2,  // "ft2"
    QC_RISCV_REG_F3,  // "ft3"
    QC_RISCV_REG_F4,  // "ft4"
    QC_RISCV_REG_F5,  // "ft5"
    QC_RISCV_REG_F6,  // "ft6"
    QC_RISCV_REG_F7,  // "ft7"
    QC_RISCV_REG_F8,  // "fs0"
    QC_RISCV_REG_F9,  // "fs1"
    QC_RISCV_REG_F10, // "fa0"
    QC_RISCV_REG_F11, // "fa1"
    QC_RISCV_REG_F12, // "fa2"
    QC_RISCV_REG_F13, // "fa3"
    QC_RISCV_REG_F14, // "fa4"
    QC_RISCV_REG_F15, // "fa5"
    QC_RISCV_REG_F16, // "fa6"
    QC_RISCV_REG_F17, // "fa7"
    QC_RISCV_REG_F18, // "fs2"
    QC_RISCV_REG_F19, // "fs3"
    QC_RISCV_REG_F20, // "fs4"
    QC_RISCV_REG_F21, // "fs5"
    QC_RISCV_REG_F22, // "fs6"
    QC_RISCV_REG_F23, // "fs7"
    QC_RISCV_REG_F24, // "fs8"
    QC_RISCV_REG_F25, // "fs9"
    QC_RISCV_REG_F26, // "fs10"
    QC_RISCV_REG_F27, // "fs11"
    QC_RISCV_REG_F28, // "ft8"
    QC_RISCV_REG_F29, // "ft9"
    QC_RISCV_REG_F30, // "ft10"
    QC_RISCV_REG_F31, // "ft11"

    QC_RISCV_REG_PC, // PC register

    QC_RISCV_REG_ENDING, // <-- mark the end of the list or registers

    //> Alias registers
    QC_RISCV_REG_ZERO = QC_RISCV_REG_X0, // "zero"
    QC_RISCV_REG_RA = QC_RISCV_REG_X1,   // "ra"
    QC_RISCV_REG_SP = QC_RISCV_REG_X2,   // "sp"
    QC_RISCV_REG_GP = QC_RISCV_REG_X3,   // "gp"
    QC_RISCV_REG_TP = QC_RISCV_REG_X4,   // "tp"
    QC_RISCV_REG_T0 = QC_RISCV_REG_X5,   // "t0"
    QC_RISCV_REG_T1 = QC_RISCV_REG_X6,   // "t1"
    QC_RISCV_REG_T2 = QC_RISCV_REG_X7,   // "t2"
    QC_RISCV_REG_S0 = QC_RISCV_REG_X8,   // "s0"
    QC_RISCV_REG_FP = QC_RISCV_REG_X8,   // "fp"
    QC_RISCV_REG_S1 = QC_RISCV_REG_X9,   // "s1"
    QC_RISCV_REG_A0 = QC_RISCV_REG_X10,  // "a0"
    QC_RISCV_REG_A1 = QC_RISCV_REG_X11,  // "a1"
    QC_RISCV_REG_A2 = QC_RISCV_REG_X12,  // "a2"
    QC_RISCV_REG_A3 = QC_RISCV_REG_X13,  // "a3"
    QC_RISCV_REG_A4 = QC_RISCV_REG_X14,  // "a4"
    QC_RISCV_REG_A5 = QC_RISCV_REG_X15,  // "a5"
    QC_RISCV_REG_A6 = QC_RISCV_REG_X16,  // "a6"
    QC_RISCV_REG_A7 = QC_RISCV_REG_X17,  // "a7"
    QC_RISCV_REG_S2 = QC_RISCV_REG_X18,  // "s2"
    QC_RISCV_REG_S3 = QC_RISCV_REG_X19,  // "s3"
    QC_RISCV_REG_S4 = QC_RISCV_REG_X20,  // "s4"
    QC_RISCV_REG_S5 = QC_RISCV_REG_X21,  // "s5"
    QC_RISCV_REG_S6 = QC_RISCV_REG_X22,  // "s6"
    QC_RISCV_REG_S7 = QC_RISCV_REG_X23,  // "s7"
    QC_RISCV_REG_S8 = QC_RISCV_REG_X24,  // "s8"
    QC_RISCV_REG_S9 = QC_RISCV_REG_X25,  // "s9"
    QC_RISCV_REG_S10 = QC_RISCV_REG_X26, // "s10"
    QC_RISCV_REG_S11 = QC_RISCV_REG_X27, // "s11"
    QC_RISCV_REG_T3 = QC_RISCV_REG_X28,  // "t3"
    QC_RISCV_REG_T4 = QC_RISCV_REG_X29,  // "t4"
    QC_RISCV_REG_T5 = QC_RISCV_REG_X30,  // "t5"
    QC_RISCV_REG_T6 = QC_RISCV_REG_X31,  // "t6"

    QC_RISCV_REG_FT0 = QC_RISCV_REG_F0, // "ft0"
    QC_RISCV_REG_FT1 = QC_RISCV_REG_F1, // "ft1"
    QC_RISCV_REG_FT2 = QC_RISCV_REG_F2, // "ft2"
    QC_RISCV_REG_FT3 = QC_RISCV_REG_F3, // "ft3"
    QC_RISCV_REG_FT4 = QC_RISCV_REG_F4, // "ft4"
    QC_RISCV_REG_FT5 = QC_RISCV_REG_F5, // "ft5"
    QC_RISCV_REG_FT6 = QC_RISCV_REG_F6, // "ft6"
    QC_RISCV_REG_FT7 = QC_RISCV_REG_F7, // "ft7"
    QC_RISCV_REG_FS0 = QC_RISCV_REG_F8, // "fs0"
    QC_RISCV_REG_FS1 = QC_RISCV_REG_F9, // "fs1"

    QC_RISCV_REG_FA0 = QC_RISCV_REG_F10,  // "fa0"
    QC_RISCV_REG_FA1 = QC_RISCV_REG_F11,  // "fa1"
    QC_RISCV_REG_FA2 = QC_RISCV_REG_F12,  // "fa2"
    QC_RISCV_REG_FA3 = QC_RISCV_REG_F13,  // "fa3"
    QC_RISCV_REG_FA4 = QC_RISCV_REG_F14,  // "fa4"
    QC_RISCV_REG_FA5 = QC_RISCV_REG_F15,  // "fa5"
    QC_RISCV_REG_FA6 = QC_RISCV_REG_F16,  // "fa6"
    QC_RISCV_REG_FA7 = QC_RISCV_REG_F17,  // "fa7"
    QC_RISCV_REG_FS2 = QC_RISCV_REG_F18,  // "fs2"
    QC_RISCV_REG_FS3 = QC_RISCV_REG_F19,  // "fs3"
    QC_RISCV_REG_FS4 = QC_RISCV_REG_F20,  // "fs4"
    QC_RISCV_REG_FS5 = QC_RISCV_REG_F21,  // "fs5"
    QC_RISCV_REG_FS6 = QC_RISCV_REG_F22,  // "fs6"
    QC_RISCV_REG_FS7 = QC_RISCV_REG_F23,  // "fs7"
    QC_RISCV_REG_FS8 = QC_RISCV_REG_F24,  // "fs8"
    QC_RISCV_REG_FS9 = QC_RISCV_REG_F25,  // "fs9"
    QC_RISCV_REG_FS10 = QC_RISCV_REG_F26, // "fs10"
    QC_RISCV_REG_FS11 = QC_RISCV_REG_F27, // "fs11"
    QC_RISCV_REG_FT8 = QC_RISCV_REG_F28,  // "ft8"
    QC_RISCV_REG_FT9 = QC_RISCV_REG_F29,  // "ft9"
    QC_RISCV_REG_FT10 = QC_RISCV_REG_F30, // "ft10"
    QC_RISCV_REG_FT11 = QC_RISCV_REG_F31, // "ft11"
} qc_riscv_reg;

#ifdef __cplusplus
}
#endif

#endif
