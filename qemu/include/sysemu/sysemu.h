#ifndef SYSEMU_H
#define SYSEMU_H

struct qc_struct;

void qemu_system_reset_request(struct qc_struct*);
void qemu_system_shutdown_request(struct qc_struct*);

#endif
