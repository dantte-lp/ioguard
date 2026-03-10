#include "auth/auth_backend.h"

#include <errno.h>
#include <string.h>

static const rw_auth_backend_t *registry[RW_AUTH_BACKEND_MAX];
static int registry_count;

int rw_auth_backend_register(const rw_auth_backend_t *backend)
{
    if (backend == nullptr || backend->name == nullptr) {
        return -EINVAL;
    }

    /* Check for duplicate name */
    for (int i = 0; i < registry_count; i++) {
        if (strcmp(registry[i]->name, backend->name) == 0) {
            return -EEXIST;
        }
    }

    if (registry_count >= RW_AUTH_BACKEND_MAX) {
        return -ENOSPC;
    }

    registry[registry_count++] = backend;
    return 0;
}

const rw_auth_backend_t *rw_auth_backend_find(const char *name)
{
    if (name == nullptr) {
        return nullptr;
    }

    for (int i = 0; i < registry_count; i++) {
        if (strcmp(registry[i]->name, name) == 0) {
            return registry[i];
        }
    }

    return nullptr;
}

const rw_auth_backend_t *const *rw_auth_backend_list(int *count)
{
    if (count != nullptr) {
        *count = registry_count;
    }

    return registry;
}

void rw_auth_backend_cleanup(void)
{
    for (int i = 0; i < registry_count; i++) {
        if (registry[i]->destroy != nullptr) {
            registry[i]->destroy();
        }
        registry[i] = nullptr;
    }
    registry_count = 0;
}
