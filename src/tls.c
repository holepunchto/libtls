#include "../include/tls.h"

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
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

  X509 *certificate;
  EVP_PKEY *key;

  tls_read_cb read;
  tls_write_cb write;

  int status;
};

static int
tls__on_read (BIO *io, char *data, int len) {
  tls_t *tls = BIO_get_ex_data(io, 0);

  int res = tls->read(tls, data, len);

  BIO_clear_retry_flags(io);

  if (res == tls_retry) {
    BIO_set_retry_read(io);

    return tls_ok;
  }

  return res;
}

static int
tls__on_write (BIO *io, const char *data, int len) {
  tls_t *tls = BIO_get_ex_data(io, 0);

  int res = tls->write(tls, data, len);

  BIO_clear_retry_flags(io);

  if (res == tls_retry) {
    BIO_set_retry_write(io);

    return tls_ok;
  }

  return res;
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

  if (io == NULL) return tls_error;

  SSL_CTX *handle = SSL_CTX_new(TLS_method());

  if (handle == NULL) {
    BIO_meth_free(io);

    return tls_error;
  }

  tls_context_t *context = malloc(sizeof(tls_context_t));

  if (context == NULL) {
    SSL_CTX_free(handle);

    BIO_meth_free(io);

    return tls_error;
  }

  BIO_meth_set_read(io, tls__on_read);
  BIO_meth_set_write(io, tls__on_write);
  BIO_meth_set_ctrl(io, tls__on_ctrl);

  SSL_CTX_set_ex_data(handle, 0, (void *) context);
  SSL_CTX_set_min_proto_version(handle, TLS1_3_VERSION);

  context->handle = handle;
  context->io = io;

  *result = context;

  return tls_ok;
}

void
tls_context_destroy (tls_context_t *context) {
  SSL_CTX_free(context->handle);

  BIO_meth_free(context->io);

  free(context);
}

int
tls_init (tls_context_t *context, tls_read_cb read, tls_write_cb write, tls_t **result) {
  BIO *io = BIO_new(context->io);

  if (io == NULL) return tls_error;

  SSL *handle = SSL_new(context->handle);

  if (io == NULL) {
    BIO_free(io);

    return tls_error;
  }

  tls_t *tls = malloc(sizeof(tls_t));

  if (tls == NULL) {
    SSL_free(handle);

    BIO_free(io);

    return tls_error;
  }

  BIO_set_ex_data(io, 0, (void *) tls);
  BIO_set_init(io, true);

  SSL_set_ex_data(handle, 0, (void *) tls);
  SSL_set_bio(handle, io, io);

  tls->handle = handle;
  tls->io = io;

  tls->certificate = NULL;
  tls->key = NULL;

  tls->read = read;
  tls->write = write;

  tls->status = 0;

  *result = tls;

  return tls_ok;
}

void
tls_destroy (tls_t *tls) {
  SSL_free(tls->handle);

  if (tls->certificate) X509_free(tls->certificate);

  if (tls->key) EVP_PKEY_free(tls->key);

  free(tls);
}

int
tls_use_certificate (tls_t *tls, const char *pem, int len) {
  BIO *io = BIO_new(BIO_s_mem());
  BIO_write(io, pem, len);

  X509 *handle = PEM_read_bio_X509(io, NULL, NULL, NULL);

  BIO_free(io);

  if (handle == NULL) return tls_error;

  int res = SSL_use_certificate(tls->handle, handle);

  if (res == 0) {
    X509_free(handle);

    tls->status = SSL_get_error(tls->handle, res);

    return tls_error;
  }

  if (tls->certificate) X509_free(tls->certificate);

  tls->certificate = handle;

  return tls_ok;
}

int
tls_use_key (tls_t *tls, const char *pem, int len) {
  BIO *io = BIO_new(BIO_s_mem());
  BIO_write(io, pem, len);

  EVP_PKEY *handle = PEM_read_bio_PrivateKey(io, NULL, NULL, NULL);

  BIO_free(io);

  if (handle == NULL) return tls_error;

  int res = SSL_use_PrivateKey(tls->handle, handle);

  if (res == 0) {
    EVP_PKEY_free(handle);

    tls->status = SSL_get_error(tls->handle, res);

    return tls_error;
  }

  if (tls->key) EVP_PKEY_free(tls->key);

  tls->key = handle;

  return tls_ok;
}

int
tls_connect (tls_t *tls) {
  int res = SSL_connect(tls->handle);

  if (res < 0) {
    tls->status = SSL_get_error(tls->handle, res);

    return tls_error;
  }

  return tls_ok;
}

int
tls_accept (tls_t *tls) {
  int res = SSL_accept(tls->handle);

  if (res < 0) {
    tls->status = SSL_get_error(tls->handle, res);

    return tls_error;
  }

  return tls_ok;
}

int
tls_read (tls_t *tls, char *data, int len) {
  int res = SSL_read(tls->handle, data, len);

  if (res <= 0) {
    int err = SSL_get_error(tls->handle, res);

    if (err == SSL_ERROR_WANT_READ) return tls_retry;

    if (SSL_get_shutdown(tls->handle)) return tls_eof;

    tls->status = err;

    return tls_error;
  }

  return res;
}

int
tls_write (tls_t *tls, const char *data, int len) {
  int res = SSL_write(tls->handle, data, len);

  if (res <= 0) {
    int err = SSL_get_error(tls->handle, res);

    if (err == SSL_ERROR_WANT_WRITE) return tls_retry;

    tls->status = err;

    return tls_error;
  }

  return res;
}

int
tls_shutdown (tls_t *tls) {
  int res = SSL_shutdown(tls->handle);

  if (res < 0) {
    tls->status = SSL_get_error(tls->handle, res);

    return tls_error;
  }

  return tls_ok;
}
