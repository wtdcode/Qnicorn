/*
 * QEMU TCG support
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef SYSEMU_TCG_H
#define SYSEMU_TCG_H

#include <stdbool.h>

//#include "qc_priv.h"

struct qc_struct;

void tcg_exec_init(struct qc_struct *uc, unsigned long tb_size);

#endif
