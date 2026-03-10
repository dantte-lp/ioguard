#ifndef RINGWALL_LOG_H
#define RINGWALL_LOG_H

#include <stddef.h>
#include <sys/types.h>

/**
 * @brief Log severity levels (RFC 5424).
 */
typedef enum {
    RW_LOG_EMERG = 0,
    RW_LOG_ALERT = 1,
    RW_LOG_CRIT = 2,
    RW_LOG_ERR = 3,
    RW_LOG_WARN = 4,
    RW_LOG_NOTICE = 5,
    RW_LOG_INFO = 6,
    RW_LOG_DEBUG = 7,
} rw_log_level_t;

typedef struct rw_logger rw_logger_t;

/**
 * @brief Initialize a logger with an internal buffer for async flushing.
 * @param out  Receives the allocated logger on success.
 * @param buffer_size  Size of the internal log buffer in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_log_init(rw_logger_t **out, size_t buffer_size);

/**
 * @brief Destroy a logger. Safe to call with nullptr.
 * @param logger  Logger to destroy (may be nullptr).
 */
void rw_log_destroy(rw_logger_t *logger);

/**
 * @brief Write a log message at the given severity level.
 * @param logger     Active logger instance.
 * @param level      Severity level.
 * @param component  Component name (e.g. "worker", "tls").
 * @param msg        Log message text.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_log_write(rw_logger_t *logger, rw_log_level_t level,
                               const char *component, const char *msg);

/**
 * @brief Write a log message with RFC 5424 structured data.
 * @param logger       Active logger instance.
 * @param level        Severity level.
 * @param component    Component name.
 * @param msg          Log message text.
 * @param sd_id        Structured data ID (SD-ID).
 * @param sd_params    Array of [name, value] pairs.
 * @param param_count  Number of parameter pairs.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_log_write_sd(rw_logger_t *logger, rw_log_level_t level,
                                  const char *component, const char *msg,
                                  const char *sd_id,
                                  const char *sd_params[][2],
                                  size_t param_count);

/**
 * @brief Flush buffered log data for io_uring WRITEV.
 * @param logger    Active logger instance.
 * @param out       Destination buffer to receive flushed data.
 * @param out_size  Size of the destination buffer.
 * @return Number of bytes written to out, or negative errno on failure.
 */
[[nodiscard]] ssize_t rw_log_flush(rw_logger_t *logger, char *out,
                                   size_t out_size);

/**
 * @brief Set the minimum severity level. Messages below this are dropped.
 * @param logger     Active logger instance.
 * @param min_level  Minimum severity (0=EMERG .. 7=DEBUG).
 */
void rw_log_set_level(rw_logger_t *logger, rw_log_level_t min_level);

#endif /* RINGWALL_LOG_H */
