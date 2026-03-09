#ifndef RINGWALL_CORE_MAIN_H
#define RINGWALL_CORE_MAIN_H

/**
 * @brief Parse command-line arguments.
 * @param argc       Argument count.
 * @param argv       Argument vector.
 * @param config_path  Receives the config file path.
 * @return 0 on success, 1 if --help was requested, negative errno on error.
 */
[[nodiscard]] int rw_main_parse_args(int argc, char *argv[],
                                     const char **config_path);

/**
 * @brief Create a SOCK_SEQPACKET socketpair for IPC.
 * @param sv  Receives the two socket fds (CLOEXEC set).
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_main_create_ipc_pair(int sv[2]);

/**
 * @brief Create a SOCK_STREAM socketpair for fd passing.
 * @param sv  Receives the two socket fds (CLOEXEC set).
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_main_create_accept_pair(int sv[2]);

/**
 * @brief Create a signalfd for SIGTERM, SIGINT, SIGCHLD.
 * @return fd on success (>= 0), negative errno on error.
 */
[[nodiscard]] int rw_main_create_signalfd(void);

#endif /* RINGWALL_CORE_MAIN_H */
