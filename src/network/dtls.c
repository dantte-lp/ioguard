#include "network/dtls.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif

struct wg_dtls_ctx {
	wg_dtls_config_t config;
#ifdef USE_WOLFSSL
	WOLFSSL_CTX *ssl_ctx;
#else
	void *ssl_ctx; /* placeholder when wolfSSL not available */
#endif
};

void wg_dtls_config_init(wg_dtls_config_t *cfg)
{
	*cfg = (wg_dtls_config_t){
		.mtu = WG_DTLS_DEFAULT_MTU,
		.timeout_init_s = WG_DTLS_DEFAULT_TIMEOUT_S,
		.rekey_interval_s = WG_DTLS_DEFAULT_REKEY_S,
		.cert_file = nullptr,
		.key_file = nullptr,
		.ca_file = nullptr,
		.cipher_list = nullptr,
		.enable_cookies = true,
	};
}

int wg_dtls_config_validate(const wg_dtls_config_t *cfg)
{
	if (!cfg)
		return -EINVAL;
	if (cfg->mtu == 0)
		return -EINVAL;
	if (cfg->timeout_init_s == 0)
		return -EINVAL;
	return 0;
}

wg_dtls_ctx_t *wg_dtls_create(const wg_dtls_config_t *cfg)
{
	if (wg_dtls_config_validate(cfg) != 0)
		return nullptr;

	wg_dtls_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return nullptr;

	ctx->config = *cfg;

#ifdef USE_WOLFSSL
	ctx->ssl_ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
	if (!ctx->ssl_ctx) {
		free(ctx);
		return nullptr;
	}

	/* Set cipher list */
	const char *ciphers = cfg->cipher_list ? cfg->cipher_list
	                                       : wg_dtls_cisco_ciphers();
	wolfSSL_CTX_set_cipher_list(ctx->ssl_ctx, ciphers);

	/* Load certs if provided */
	if (cfg->cert_file) {
		if (wolfSSL_CTX_use_certificate_file(ctx->ssl_ctx,
		    cfg->cert_file, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			wolfSSL_CTX_free(ctx->ssl_ctx);
			free(ctx);
			return nullptr;
		}
	}
	if (cfg->key_file) {
		if (wolfSSL_CTX_use_PrivateKey_file(ctx->ssl_ctx,
		    cfg->key_file, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			wolfSSL_CTX_free(ctx->ssl_ctx);
			free(ctx);
			return nullptr;
		}
	}
#else
	ctx->ssl_ctx = nullptr;
#endif

	return ctx;
}

void wg_dtls_destroy(wg_dtls_ctx_t *ctx)
{
	if (!ctx)
		return;
#ifdef USE_WOLFSSL
	if (ctx->ssl_ctx)
		wolfSSL_CTX_free(ctx->ssl_ctx);
#endif
	explicit_bzero(ctx, sizeof(*ctx));
	free(ctx);
}

uint32_t wg_dtls_get_mtu(const wg_dtls_ctx_t *ctx)
{
	return ctx->config.mtu;
}

const char *wg_dtls_cisco_ciphers(void)
{
	return "DHE-RSA-AES256-SHA:AES256-SHA:DHE-RSA-AES128-SHA:AES128-SHA";
}
