#include "../include/tls.h"

#include <openssl/base.h>
#include <openssl/ssl.h>
#include <stddef.h>

struct tls_context_s {
  SSL_CTX *handle;
};

struct tls_s {
  SSL *handle;
};

int
tls_context_init (tls_context_t **result) {
  SSL_CTX *handle = SSL_CTX_new(TLS_method());

  if (handle == NULL) return -1;

  SSL_CTX_set_min_proto_version(handle, TLS1_3_VERSION);

  tls_context_t *context = malloc(sizeof(tls_context_t));

  if (context == NULL) {
    SSL_CTX_free(handle);

    return -1;
  }

  SSL_CTX_set_ex_data(handle, 0, (void *) context);

  context->handle = handle;

  *result = context;

  return 0;
}

void
tls_context_destroy (tls_context_t *context) {
  SSL_CTX_free(context->handle);

  free(context);
}

int
tls_init (tls_context_t *context, tls_t **result) {
  SSL *handle = SSL_new(context->handle);

  if (handle == NULL) return -1;

  tls_t *tls = malloc(sizeof(tls_t));

  if (tls == NULL) {
    SSL_free(handle);

    return -1;
  }

  SSL_set_ex_data(handle, 0, (void *) tls);

  tls->handle = handle;

  *result = tls;

  return 0;
}

void
tls_destroy (tls_t *tls) {
  SSL_free(tls->handle);

  free(tls);
}
