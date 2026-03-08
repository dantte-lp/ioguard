/**
 * @file fuzz_ipc.c
 * @brief LibFuzzer target for IPC protobuf-c message unpacking.
 *
 * Feeds arbitrary bytes to rw_ipc_unpack_auth_request() and
 * rw_ipc_unpack_auth_response() to find crashes or UB in the
 * protobuf-c deserialization path.
 */

#include <ipc/messages.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Fuzz auth request unpacking */
	rw_ipc_auth_request_t req = {0};
	int rc = rw_ipc_unpack_auth_request(data, size, &req);
	if (rc == 0) {
		rw_ipc_free_auth_request(&req);
	}

	/* Fuzz auth response unpacking */
	rw_ipc_auth_response_t resp = {0};
	rc = rw_ipc_unpack_auth_response(data, size, &resp);
	if (rc == 0) {
		rw_ipc_free_auth_response(&resp);
	}

	/* Fuzz session validate unpacking */
	rw_ipc_session_validate_t val = {0};
	rc = rw_ipc_unpack_session_validate(data, size, &val);
	if (rc == 0) {
		rw_ipc_free_session_validate(&val);
	}

	/* Fuzz worker status unpacking */
	rw_ipc_worker_status_t status = {0};
	(void)rw_ipc_unpack_worker_status(data, size, &status);

	return 0;
}
