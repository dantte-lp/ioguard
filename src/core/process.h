#ifndef IOGUARD_CORE_PROCESS_H
#define IOGUARD_CORE_PROCESS_H

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    int pidfd;
} iog_process_t;

[[nodiscard]] int iog_process_spawn(iog_process_t *proc, const char *path,
                                    const char *const argv[]);

[[nodiscard]] int iog_process_wait(iog_process_t *proc, int *exit_status, uint32_t timeout_ms);

[[nodiscard]] int iog_process_signal(iog_process_t *proc, int sig);

void iog_process_cleanup(iog_process_t *proc);

#endif /* IOGUARD_CORE_PROCESS_H */
