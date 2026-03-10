#define _GNU_SOURCE

#include "log/rw_log.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef USE_STUMPLESS
#include <stumpless.h>
#endif

struct rw_logger {
#ifdef USE_STUMPLESS
    struct stumpless_target *target;
#endif
    char *buffer;
    size_t buffer_size;
    rw_log_level_t min_level;
    size_t write_pos;  /* tracks write position (both paths) */
    size_t read_pos;   /* tracks read position (stumpless path) */
};

constexpr size_t IOG_LOG_MIN_BUFFER = 512;

#ifdef USE_STUMPLESS

static enum stumpless_severity level_to_stumpless(rw_log_level_t level)
{
    switch (level) {
    case IOG_LOG_EMERG:
        return STUMPLESS_SEVERITY_EMERG;
    case IOG_LOG_ALERT:
        return STUMPLESS_SEVERITY_ALERT;
    case IOG_LOG_CRIT:
        return STUMPLESS_SEVERITY_CRIT;
    case IOG_LOG_ERR:
        return STUMPLESS_SEVERITY_ERR;
    case IOG_LOG_WARN:
        return STUMPLESS_SEVERITY_WARNING;
    case IOG_LOG_NOTICE:
        return STUMPLESS_SEVERITY_NOTICE;
    case IOG_LOG_INFO:
        return STUMPLESS_SEVERITY_INFO;
    case IOG_LOG_DEBUG:
        return STUMPLESS_SEVERITY_DEBUG;
    }
    return STUMPLESS_SEVERITY_INFO;
}

[[nodiscard]] int rw_log_init(rw_logger_t **out, size_t buffer_size)
{
    if (out == nullptr || buffer_size < IOG_LOG_MIN_BUFFER) {
        return -EINVAL;
    }

    rw_logger_t *logger = calloc(1, sizeof(*logger));
    if (logger == nullptr) {
        return -ENOMEM;
    }

    logger->buffer = calloc(1, buffer_size);
    if (logger->buffer == nullptr) {
        free(logger);
        return -ENOMEM;
    }

    logger->buffer_size = buffer_size;
    logger->min_level = IOG_LOG_DEBUG;

    logger->target =
        stumpless_open_buffer_target("ioguard", logger->buffer, buffer_size);
    if (logger->target == nullptr) {
        free(logger->buffer);
        free(logger);
        return -EIO;
    }

    *out = logger;
    return 0;
}

void rw_log_destroy(rw_logger_t *logger)
{
    if (logger == nullptr) {
        return;
    }
    if (logger->target != nullptr) {
        stumpless_close_buffer_target(logger->target);
    }
    free(logger->buffer);
    free(logger);
}

[[nodiscard]] int rw_log_write(rw_logger_t *logger, rw_log_level_t level,
                               const char *component, const char *msg)
{
    if (logger == nullptr || component == nullptr || msg == nullptr) {
        return -EINVAL;
    }
    if (level > logger->min_level) {
        return 0;
    }

    struct stumpless_entry *entry = stumpless_new_entry(
        STUMPLESS_FACILITY_DAEMON, level_to_stumpless(level), component,
        "-", msg);
    if (entry == nullptr) {
        return -ENOMEM;
    }

    int ret = stumpless_add_entry(logger->target, entry);
    stumpless_destroy_entry_and_contents(entry);

    if (ret >= 0) {
        /* Scan our buffer to find how far stumpless has written.
         * We own the buffer and it was zeroed at init, so the first
         * NUL byte after write_pos marks the end of written data. */
        size_t pos = logger->write_pos;
        while (pos < logger->buffer_size && logger->buffer[pos] != '\0') {
            pos++;
        }
        logger->write_pos = pos;
    }

    return (ret >= 0) ? 0 : -EIO;
}

[[nodiscard]] int rw_log_write_sd(rw_logger_t *logger, rw_log_level_t level,
                                  const char *component, const char *msg,
                                  const char *sd_id,
                                  const char *sd_params[][2],
                                  size_t param_count)
{
    if (logger == nullptr || component == nullptr || msg == nullptr ||
        sd_id == nullptr) {
        return -EINVAL;
    }
    if (level > logger->min_level) {
        return 0;
    }

    struct stumpless_entry *entry = stumpless_new_entry(
        STUMPLESS_FACILITY_DAEMON, level_to_stumpless(level), component,
        "-", msg);
    if (entry == nullptr) {
        return -ENOMEM;
    }

    struct stumpless_element *elem = stumpless_new_element(sd_id);
    if (elem == nullptr) {
        stumpless_destroy_entry_and_contents(entry);
        return -ENOMEM;
    }

    for (size_t i = 0; i < param_count; i++) {
        struct stumpless_param *param =
            stumpless_new_param(sd_params[i][0], sd_params[i][1]);
        if (param == nullptr) {
            stumpless_destroy_entry_and_contents(entry);
            return -ENOMEM;
        }
        stumpless_add_param(elem, param);
    }

    stumpless_add_element(entry, elem);

    int ret = stumpless_add_entry(logger->target, entry);
    stumpless_destroy_entry_and_contents(entry);

    if (ret >= 0) {
        size_t pos = logger->write_pos;
        while (pos < logger->buffer_size && logger->buffer[pos] != '\0') {
            pos++;
        }
        logger->write_pos = pos;
    }

    return (ret >= 0) ? 0 : -EIO;
}

[[nodiscard]] ssize_t rw_log_flush(rw_logger_t *logger, char *out,
                                   size_t out_size)
{
    if (logger == nullptr || out == nullptr || out_size == 0) {
        return -EINVAL;
    }

    /* We own the buffer and track write_pos / read_pos ourselves.
     * Copy unread data directly from our buffer into the output. */
    size_t available = logger->write_pos - logger->read_pos;
    if (available == 0) {
        return 0;
    }

    size_t to_copy = available;
    if (to_copy > out_size) {
        to_copy = out_size;
    }

    memcpy(out, logger->buffer + logger->read_pos, to_copy);
    logger->read_pos += to_copy;
    return (ssize_t)to_copy;
}

void rw_log_set_level(rw_logger_t *logger, rw_log_level_t min_level)
{
    if (logger == nullptr) {
        return;
    }
    logger->min_level = min_level;
}

#else /* !USE_STUMPLESS — stderr fallback */

static const char *level_name(rw_log_level_t level)
{
    static const char *names[] = {
        "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG",
    };
    if (level > IOG_LOG_DEBUG) {
        return "UNKNOWN";
    }
    return names[level];
}

[[nodiscard]] int rw_log_init(rw_logger_t **out, size_t buffer_size)
{
    if (out == nullptr || buffer_size < IOG_LOG_MIN_BUFFER) {
        return -EINVAL;
    }

    rw_logger_t *logger = calloc(1, sizeof(*logger));
    if (logger == nullptr) {
        return -ENOMEM;
    }

    logger->buffer = calloc(1, buffer_size);
    if (logger->buffer == nullptr) {
        free(logger);
        return -ENOMEM;
    }

    logger->buffer_size = buffer_size;
    logger->min_level = IOG_LOG_DEBUG;
    logger->write_pos = 0;

    *out = logger;
    return 0;
}

void rw_log_destroy(rw_logger_t *logger)
{
    if (logger == nullptr) {
        return;
    }
    free(logger->buffer);
    free(logger);
}

static int fallback_append(rw_logger_t *logger, rw_log_level_t level,
                           const char *component, const char *msg,
                           const char *sd_extra)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_buf;
    gmtime_r(&ts.tv_sec, &tm_buf);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    size_t remaining = logger->buffer_size - logger->write_pos;
    if (remaining < 2) {
        return -ENOSPC;
    }

    int written;
    if (sd_extra != nullptr) {
        written = snprintf(logger->buffer + logger->write_pos, remaining,
                           "%sZ %s [%s] %s %s\n", timestamp,
                           level_name(level), component, msg, sd_extra);
    } else {
        written = snprintf(logger->buffer + logger->write_pos, remaining,
                           "%sZ %s [%s] %s\n", timestamp, level_name(level),
                           component, msg);
    }

    if (written < 0) {
        return -EIO;
    }
    if ((size_t)written >= remaining) {
        /* Truncated but still usable */
        logger->write_pos = logger->buffer_size;
    } else {
        logger->write_pos += (size_t)written;
    }

    /* Also emit to stderr for immediate visibility */
    if (sd_extra != nullptr) {
        fprintf(stderr, "%sZ %s [%s] %s %s\n", timestamp, level_name(level),
                component, msg, sd_extra);
    } else {
        fprintf(stderr, "%sZ %s [%s] %s\n", timestamp, level_name(level),
                component, msg);
    }

    return 0;
}

[[nodiscard]] int rw_log_write(rw_logger_t *logger, rw_log_level_t level,
                               const char *component, const char *msg)
{
    if (logger == nullptr || component == nullptr || msg == nullptr) {
        return -EINVAL;
    }
    if (level > logger->min_level) {
        return 0;
    }

    return fallback_append(logger, level, component, msg, nullptr);
}

[[nodiscard]] int rw_log_write_sd(rw_logger_t *logger, rw_log_level_t level,
                                  const char *component, const char *msg,
                                  const char *sd_id,
                                  const char *sd_params[][2],
                                  size_t param_count)
{
    if (logger == nullptr || component == nullptr || msg == nullptr ||
        sd_id == nullptr) {
        return -EINVAL;
    }
    if (level > logger->min_level) {
        return 0;
    }

    /* Build structured data string: [sd_id k1="v1" k2="v2"] */
    char sd_buf[512];
    int pos = snprintf(sd_buf, sizeof(sd_buf), "[%s", sd_id);
    if (pos < 0 || (size_t)pos >= sizeof(sd_buf)) {
        return -ENOSPC;
    }

    for (size_t i = 0; i < param_count; i++) {
        int n = snprintf(sd_buf + pos, sizeof(sd_buf) - (size_t)pos,
                         " %s=\"%s\"", sd_params[i][0], sd_params[i][1]);
        if (n < 0) {
            return -EIO;
        }
        pos += n;
        if ((size_t)pos >= sizeof(sd_buf)) {
            break;
        }
    }
    if ((size_t)pos < sizeof(sd_buf) - 1) {
        sd_buf[pos] = ']';
        sd_buf[pos + 1] = '\0';
    }

    return fallback_append(logger, level, component, msg, sd_buf);
}

[[nodiscard]] ssize_t rw_log_flush(rw_logger_t *logger, char *out,
                                   size_t out_size)
{
    if (logger == nullptr || out == nullptr || out_size == 0) {
        return -EINVAL;
    }

    size_t to_copy = logger->write_pos;
    if (to_copy > out_size) {
        to_copy = out_size;
    }

    if (to_copy > 0) {
        memcpy(out, logger->buffer, to_copy);
    }

    /* Shift remaining data (if partial read) */
    if (to_copy < logger->write_pos) {
        memmove(logger->buffer, logger->buffer + to_copy,
                logger->write_pos - to_copy);
        logger->write_pos -= to_copy;
    } else {
        logger->write_pos = 0;
    }

    return (ssize_t)to_copy;
}

void rw_log_set_level(rw_logger_t *logger, rw_log_level_t min_level)
{
    if (logger == nullptr) {
        return;
    }
    logger->min_level = min_level;
}

#endif /* USE_STUMPLESS */
