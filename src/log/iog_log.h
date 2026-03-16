#ifndef IOGUARD_LOG_H
#define IOGUARD_LOG_H

#include <stddef.h>
#include <sys/types.h>

/**
 * @brief Log severity levels (RFC 5424).
 */
typedef enum {
    IOG_LOG_EMERG = 0,
    IOG_LOG_ALERT = 1,
    IOG_LOG_CRIT = 2,
    IOG_LOG_ERR = 3,
    IOG_LOG_WARN = 4,
    IOG_LOG_NOTICE = 5,
    IOG_LOG_INFO = 6,
    IOG_LOG_DEBUG = 7,
} iog_log_level_t;

typedef struct iog_logger iog_logger_t;

/**
 * @brief Initialize a logger with an internal buffer for async flushing.
 * @param out  Receives the allocated logger on success.
 * @param buffer_size  Size of the internal log buffer in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_log_init(iog_logger_t **out, size_t buffer_size);

/**
 * @brief Destroy a logger. Safe to call with nullptr.
 * @param logger  Logger to destroy (may be nullptr).
 */
void iog_log_destroy(iog_logger_t *logger);

/**
 * @brief Write a log message at the given severity level.
 * @param logger     Active logger instance.
 * @param level      Severity level.
 * @param component  Component name (e.g. "worker", "tls").
 * @param msg        Log message text.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_log_write(iog_logger_t *logger, iog_log_level_t level, const char *component,
                                const char *msg);

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
[[nodiscard]] int iog_log_write_sd(iog_logger_t *logger, iog_log_level_t level,
                                   const char *component, const char *msg, const char *sd_id,
                                   const char *sd_params[][2], size_t param_count);

/**
 * @brief Flush buffered log data for io_uring WRITEV.
 * @param logger    Active logger instance.
 * @param out       Destination buffer to receive flushed data.
 * @param out_size  Size of the destination buffer.
 * @return Number of bytes written to out, or negative errno on failure.
 */
[[nodiscard]] ssize_t iog_log_flush(iog_logger_t *logger, char *out, size_t out_size);

/**
 * @brief Set the minimum severity level. Messages below this are dropped.
 * @param logger     Active logger instance.
 * @param min_level  Minimum severity (0=EMERG .. 7=DEBUG).
 */
void iog_log_set_level(iog_logger_t *logger, iog_log_level_t min_level);

#endif /* IOGUARD_LOG_H */
