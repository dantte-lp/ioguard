#include "storage/mdbx.h"

#include <errno.h>
#include <signal.h>
#include <string.h>

/**
 * Convert MDBX error codes to negative errno values that the rest of the
 * codebase expects.  Only the codes we actually encounter are mapped; anything
 * else falls through as -EIO.
 */
static int mdbx_rc_to_errno(int rc)
{
	switch (rc) {
	case MDBX_SUCCESS:   return 0;
	case MDBX_NOTFOUND:  return -ENOENT;
	case MDBX_KEYEXIST:  return -EEXIST;
	case MDBX_MAP_FULL:  return -ENOSPC;
	case MDBX_EINVAL:    return -EINVAL;
	case MDBX_EACCESS:   return -EACCES;
	case MDBX_ENOMEM:    return -ENOMEM;
	default:             return -EIO;
	}
}

/* HSR callback: evict stale readers whose process no longer exists. */
static int hsr_callback(const MDBX_env *env, const MDBX_txn *txn,
                         mdbx_pid_t pid, mdbx_tid_t tid,
                         uint64_t laggard, unsigned gap,
                         size_t space, int retry)
{
	(void)env;
	(void)txn;
	(void)tid;
	(void)laggard;
	(void)gap;
	(void)space;
	(void)retry;

	/* If the process is dead, tell libmdbx to clear the reader slot. */
	if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
		return 2; /* reader process is gone — reset slot */

	return 0; /* still alive, do nothing */
}

int rw_mdbx_init(rw_mdbx_ctx_t *ctx, const char *path)
{
	if (ctx == nullptr || path == nullptr)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	int rc = mdbx_env_create(&ctx->env);
	if (rc != MDBX_SUCCESS)
		return mdbx_rc_to_errno(rc);

	rc = mdbx_env_set_geometry(ctx->env,
	                           (intptr_t)RW_MDBX_SIZE_LOWER,  /* lower */
	                           -1,                             /* now = default */
	                           (intptr_t)RW_MDBX_SIZE_UPPER,   /* upper */
	                           (intptr_t)RW_MDBX_GROWTH_STEP,  /* growth */
	                           (intptr_t)RW_MDBX_SHRINK_THRESHOLD, /* shrink */
	                           -1);                            /* pagesize = default */
	if (rc != MDBX_SUCCESS)
		goto err_close;

	rc = mdbx_env_set_maxreaders(ctx->env, RW_MDBX_MAX_READERS);
	if (rc != MDBX_SUCCESS)
		goto err_close;

	rc = mdbx_env_set_maxdbs(ctx->env, RW_MDBX_MAX_DBS);
	if (rc != MDBX_SUCCESS)
		goto err_close;

	rc = mdbx_env_set_hsr(ctx->env, hsr_callback);
	if (rc != MDBX_SUCCESS)
		goto err_close;

	MDBX_env_flags_t flags = MDBX_NOSUBDIR | MDBX_SAFE_NOSYNC |
	                         MDBX_LIFORECLAIM;
	rc = mdbx_env_open(ctx->env, path, flags, 0600);
	if (rc != MDBX_SUCCESS)
		goto err_close;

	/* Open the named "sessions" sub-database inside a write txn. */
	MDBX_txn *txn = nullptr;
	rc = mdbx_txn_begin(ctx->env, nullptr, 0, &txn);
	if (rc != MDBX_SUCCESS)
		goto err_close;

	rc = mdbx_dbi_open(txn, "sessions", MDBX_CREATE, &ctx->dbi_sessions);
	if (rc != MDBX_SUCCESS) {
		mdbx_txn_abort(txn);
		goto err_close;
	}

	rc = mdbx_txn_commit(txn);
	if (rc != MDBX_SUCCESS)
		goto err_close;

	return 0;

err_close:
	mdbx_env_close(ctx->env);
	ctx->env = nullptr;
	return mdbx_rc_to_errno(rc);
}

void rw_mdbx_close(rw_mdbx_ctx_t *ctx)
{
	if (ctx == nullptr || ctx->env == nullptr)
		return;

	mdbx_env_close(ctx->env);
	ctx->env = nullptr;
}

int rw_mdbx_session_create(rw_mdbx_ctx_t *ctx,
                            const rw_session_record_t *session)
{
	if (ctx == nullptr || ctx->env == nullptr || session == nullptr)
		return -EINVAL;

	MDBX_txn *txn = nullptr;
	int rc = mdbx_txn_begin(ctx->env, nullptr, 0, &txn);
	if (rc != MDBX_SUCCESS)
		return mdbx_rc_to_errno(rc);

	MDBX_val key = {.iov_base = (void *)session->session_id,
	                .iov_len  = RW_SESSION_ID_LEN};
	MDBX_val data = {.iov_base = (void *)session,
	                 .iov_len  = sizeof(*session)};

	rc = mdbx_put(txn, ctx->dbi_sessions, &key, &data, MDBX_NOOVERWRITE);
	if (rc != MDBX_SUCCESS) {
		mdbx_txn_abort(txn);
		return mdbx_rc_to_errno(rc);
	}

	rc = mdbx_txn_commit(txn);
	return mdbx_rc_to_errno(rc);
}

int rw_mdbx_session_lookup(rw_mdbx_ctx_t *ctx,
                            const uint8_t session_id[RW_SESSION_ID_LEN],
                            rw_session_record_t *out)
{
	if (ctx == nullptr || ctx->env == nullptr ||
	    session_id == nullptr || out == nullptr)
		return -EINVAL;

	MDBX_txn *txn = nullptr;
	int rc = mdbx_txn_begin(ctx->env, nullptr, MDBX_TXN_RDONLY, &txn);
	if (rc != MDBX_SUCCESS)
		return mdbx_rc_to_errno(rc);

	MDBX_val key = {.iov_base = (void *)session_id,
	                .iov_len  = RW_SESSION_ID_LEN};
	MDBX_val data = {0};

	rc = mdbx_get(txn, ctx->dbi_sessions, &key, &data);
	if (rc == MDBX_SUCCESS) {
		memcpy(out, data.iov_base, sizeof(*out));
	}

	int err = mdbx_rc_to_errno(rc);
	mdbx_txn_abort(txn);
	return err;
}

int rw_mdbx_session_delete(rw_mdbx_ctx_t *ctx,
                            const uint8_t session_id[RW_SESSION_ID_LEN])
{
	if (ctx == nullptr || ctx->env == nullptr || session_id == nullptr)
		return -EINVAL;

	MDBX_txn *txn = nullptr;
	int rc = mdbx_txn_begin(ctx->env, nullptr, 0, &txn);
	if (rc != MDBX_SUCCESS)
		return mdbx_rc_to_errno(rc);

	MDBX_val key = {.iov_base = (void *)session_id,
	                .iov_len  = RW_SESSION_ID_LEN};

	rc = mdbx_del(txn, ctx->dbi_sessions, &key, nullptr);
	if (rc != MDBX_SUCCESS) {
		mdbx_txn_abort(txn);
		return mdbx_rc_to_errno(rc);
	}

	rc = mdbx_txn_commit(txn);
	return mdbx_rc_to_errno(rc);
}

int rw_mdbx_session_count(rw_mdbx_ctx_t *ctx, uint32_t *count)
{
	if (ctx == nullptr || ctx->env == nullptr || count == nullptr)
		return -EINVAL;

	MDBX_txn *txn = nullptr;
	int rc = mdbx_txn_begin(ctx->env, nullptr, MDBX_TXN_RDONLY, &txn);
	if (rc != MDBX_SUCCESS)
		return mdbx_rc_to_errno(rc);

	MDBX_stat stat;
	rc = mdbx_dbi_stat(txn, ctx->dbi_sessions, &stat, sizeof(stat));
	if (rc == MDBX_SUCCESS)
		*count = (uint32_t)stat.ms_entries;

	int err = mdbx_rc_to_errno(rc);
	mdbx_txn_abort(txn);
	return err;
}

int rw_mdbx_session_iterate(rw_mdbx_ctx_t *ctx,
                             rw_mdbx_session_iter_fn fn, void *userdata)
{
	if (ctx == nullptr || ctx->env == nullptr || fn == nullptr)
		return -EINVAL;

	MDBX_txn *txn = nullptr;
	int rc = mdbx_txn_begin(ctx->env, nullptr, MDBX_TXN_RDONLY, &txn);
	if (rc != MDBX_SUCCESS)
		return mdbx_rc_to_errno(rc);

	MDBX_cursor *cursor = nullptr;
	rc = mdbx_cursor_open(txn, ctx->dbi_sessions, &cursor);
	if (rc != MDBX_SUCCESS) {
		mdbx_txn_abort(txn);
		return mdbx_rc_to_errno(rc);
	}

	MDBX_val key, data;
	int ret = 0;
	rc = mdbx_cursor_get(cursor, &key, &data, MDBX_FIRST);
	while (rc == MDBX_SUCCESS) {
		rw_session_record_t record;
		memcpy(&record, data.iov_base, sizeof(record));

		ret = fn(&record, userdata);
		if (ret != 0)
			break;

		rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
	}

	mdbx_cursor_close(cursor);
	mdbx_txn_abort(txn);

	/* MDBX_NOTFOUND at end of cursor is normal, not an error. */
	if (rc == MDBX_NOTFOUND)
		rc = MDBX_SUCCESS;

	if (ret != 0)
		return ret;
	return mdbx_rc_to_errno(rc);
}
