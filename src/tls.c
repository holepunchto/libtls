#include "../include/tls.h"

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>

struct tls_context_s {
  SSL_CTX *handle;
  BIO_METHOD *io;
};

struct tls_s {
  SSL *handle;
  BIO *io;
};

static int
tls__on_read (BIO *io, char *buf, int len) {
  tls_t *tls = BIO_get_ex_data(io, 0);

  return 0;
}

static int
tls__on_write (BIO *io, const char *buf, int len) {
  tls_t *tls = BIO_get_ex_data(io, 0);

  return 0;
}

static long
tls__on_ctrl (BIO *io, int cmd, long argc, void *argv) {
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    return 1;

  default:
    return 0;
  }
}

int
tls_context_init (tls_context_t **result) {
  BIO_METHOD *io = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "callback");

  if (io == NULL) return -1;

  SSL_CTX *handle = SSL_CTX_new(TLS_method());

  if (handle == NULL) {
    BIO_meth_free(io);

    return -1;
  }

  tls_context_t *context = malloc(sizeof(tls_context_t));

  if (context == NULL) {
    SSL_CTX_free(handle);

    BIO_meth_free(io);

    return -1;
  }

  BIO_meth_set_read(io, tls__on_read);

  BIO_meth_set_write(io, tls__on_write);

  BIO_meth_set_ctrl(io, tls__on_ctrl);

  SSL_CTX_set_min_proto_version(handle, TLS1_3_VERSION);

  SSL_CTX_set_ex_data(handle, 0, (void *) context);

  context->handle = handle;

  *result = context;

  return 0;
}

void
tls_context_destroy (tls_context_t *context) {
  SSL_CTX_free(context->handle);

  BIO_meth_free(context->io);

  free(context);
}

int
tls_init (tls_context_t *context, tls_t **result) {
  BIO *io = BIO_new(context->io);

  if (io == NULL) return -1;

  SSL *handle = SSL_new(context->handle);

  if (io == NULL) {
    BIO_free(io);

    return -1;
  }

  tls_t *tls = malloc(sizeof(tls_t));

  if (tls == NULL) {
    SSL_free(handle);

    BIO_free(io);

    return -1;
  }

  BIO_set_ex_data(io, 0, (void *) tls);

  BIO_set_init(io, true);

  SSL_set_ex_data(handle, 0, (void *) tls);

  SSL_set_bio(handle, io, io);

  tls->handle = handle;

  *result = tls;

  return 0;
}

void
tls_destroy (tls_t *tls) {
  SSL_free(tls->handle);

  BIO_free(tls->io);

  free(tls);
}
