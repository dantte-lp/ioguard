#include "core/main.h"
#include "config/config.h"
#include "core/secmod.h"
#include "core/worker_loop.h"
#include "ipc/fdpass.h"
#include "security/sandbox.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

constexpr char RW_DEFAULT_CONFIG_PATH[] = "/etc/ringwall/ringwall.toml";

int rw_main_parse_args(int argc, char *argv[], const char **config_path)
{
    *config_path = RW_DEFAULT_CONFIG_PATH;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            *config_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return 1;
        }
    }
    return 0;
}

int rw_main_create_ipc_pair(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
        return -errno;
    }
    return 0;
}

int rw_main_create_accept_pair(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
        return -errno;
    }
    return 0;
}

int rw_main_create_signalfd(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        return -errno;
    }
    int fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    return fd;
}

#ifndef RW_TESTING
int main(int argc, char *argv[])
{
    const char *config_path;
    int rc = rw_main_parse_args(argc, argv, &config_path);
    if (rc == 1) {
        fprintf(stdout, "Usage: ringwall [--config path]\n");
        return EXIT_SUCCESS;
    }

    /* Load configuration */
    rw_config_t config;
    rw_config_set_defaults(&config);
    rc = rw_config_load(config_path, &config);
    if (rc < 0) {
        fprintf(stderr, "Failed to load config: %s\n", strerror(-rc));
        return EXIT_FAILURE;
    }

    /* Create IPC socketpair for auth-mod */
    int authmod_sv[2];
    rc = rw_main_create_ipc_pair(authmod_sv);
    if (rc < 0) {
        goto cleanup_config;
    }

    /* Create accept socketpair for worker (fd passing) */
    int worker_sv[2];
    rc = rw_main_create_accept_pair(worker_sv);
    if (rc < 0) {
        goto cleanup_authmod_sv;
    }

    /* Fork auth-mod */
    pid_t authmod_pid = fork();
    if (authmod_pid < 0) {
        rc = -errno;
        goto cleanup_worker_sv;
    }
    if (authmod_pid == 0) {
        close(authmod_sv[0]);
        close(worker_sv[0]);
        close(worker_sv[1]);
        rw_secmod_ctx_t secmod;
        rc = rw_secmod_init(&secmod, authmod_sv[1], &config);
        if (rc == 0) {
            rc = rw_secmod_run(&secmod);
            rw_secmod_destroy(&secmod);
        }
        rw_config_free(&config);
        _exit(rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }
    close(authmod_sv[1]);

    /* Fork worker */
    pid_t worker_pid = fork();
    if (worker_pid < 0) {
        rc = -errno;
        goto cleanup_authmod;
    }
    if (worker_pid == 0) {
        close(worker_sv[0]);
        close(authmod_sv[0]);

        rw_worker_config_t wcfg;
        rw_worker_config_init(&wcfg);
        rw_worker_loop_config_t wlcfg = {
            .accept_fd = worker_sv[1],
            .ipc_fd = -1,
            .worker_cfg = &wcfg,
        };

        rw_worker_loop_t loop;
        rc = rw_worker_loop_init(&loop, &wlcfg);
        if (rc == 0) {
            rc = rw_worker_loop_run(&loop);
            rw_worker_loop_destroy(&loop);
        }

        close(worker_sv[1]);
        rw_config_free(&config);
        _exit(rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }
    close(worker_sv[1]);

    /* Main: signal loop */
    int sigfd = rw_main_create_signalfd();
    if (sigfd < 0) {
        rc = sigfd;
        goto cleanup_children;
    }

    struct signalfd_siginfo ssi;
    bool running = true;
    while (running) {
        ssize_t n = read(sigfd, &ssi, sizeof(ssi));
        if (n != (ssize_t)sizeof(ssi)) {
            break; /* blocking fd — partial read is fatal */
        }
        if (ssi.ssi_signo == SIGTERM || ssi.ssi_signo == SIGINT) {
            running = false;
        } else if (ssi.ssi_signo == SIGCHLD) {
            int status;
            waitpid(-1, &status, WNOHANG);
        }
    }

    /* Graceful shutdown */
    kill(worker_pid, SIGTERM);
    kill(authmod_pid, SIGTERM);
    waitpid(worker_pid, nullptr, 0);
    waitpid(authmod_pid, nullptr, 0);
    close(sigfd);
    rc = 0;

cleanup_children:
cleanup_authmod:
    close(authmod_sv[0]);
cleanup_worker_sv:
    close(worker_sv[0]);
cleanup_authmod_sv:
cleanup_config:
    rw_config_free(&config);
    return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
#endif /* RW_TESTING */
