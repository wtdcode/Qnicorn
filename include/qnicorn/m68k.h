/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef QNICORN_M68K_H
#define QNICORN_M68K_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

//> M68K CPU
typedef enum qc_cpu_m68k {
    QC_CPU_M5206_CPU = 0,
    QC_CPU_M68000_CPU,
    QC_CPU_M68020_CPU,
    QC_CPU_M68030_CPU,
    QC_CPU_M68040_CPU,
    QC_CPU_M68060_CPU,
    QC_CPU_M5208_CPU,
    QC_CPU_CFV4E_CPU,
    QC_CPU_ANY_CPU,
} qc_cpu_m68k;

//> M68K registers
typedef enum qc_m68k_reg {
    QC_M68K_REG_INVALID = 0,

    QC_M68K_REG_A0,
    QC_M68K_REG_A1,
    QC_M68K_REG_A2,
    QC_M68K_REG_A3,
    QC_M68K_REG_A4,
    QC_M68K_REG_A5,
    QC_M68K_REG_A6,
    QC_M68K_REG_A7,

    QC_M68K_REG_D0,
    QC_M68K_REG_D1,
    QC_M68K_REG_D2,
    QC_M68K_REG_D3,
    QC_M68K_REG_D4,
    QC_M68K_REG_D5,
    QC_M68K_REG_D6,
    QC_M68K_REG_D7,

    QC_M68K_REG_SR,
    QC_M68K_REG_PC,

    QC_M68K_REG_ENDING, // <-- mark the end of the list of registers
} qc_m68k_reg;

#ifdef __cplusplus
}
#endif

#endif
