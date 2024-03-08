#include "fixtures/cert.key.h"
#include "fixtures/cert.pem.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <tls.h>
#include <unistd.h>

static int a_pipe[2];
static int b_pipe[2];

static int
on_a_read (tls_t *tls, char *data, int len) {
  int e = read(a_pipe[0], data, len);
  if (e < 0 && errno == EAGAIN) return tls_retry;
  return e;
}

static int
on_a_write (tls_t *tls, const char *data, int len) {
  int e = write(b_pipe[1], data, len);
  if (e < 0 && errno == EAGAIN) return tls_retry;
  return e;
}

static int
on_b_read (tls_t *tls, char *data, int len) {
  int e = read(b_pipe[0], data, len);
  if (e < 0 && errno == EAGAIN) return tls_retry;
  return e;
}

static int
on_b_write (tls_t *tls, const char *data, int len) {
  int e = write(a_pipe[1], data, len);
  if (e < 0 && errno == EAGAIN) return tls_retry;
  return e;
}

int
main () {
  int e;

  e = pipe(a_pipe);
  assert(e == 0);

  e = fcntl(a_pipe[0], F_SETFL, fcntl(a_pipe[0], F_GETFL) | O_NONBLOCK);
  assert(e == 0);

  e = pipe(b_pipe);
  assert(e == 0);

  e = fcntl(b_pipe[0], F_SETFL, fcntl(b_pipe[0], F_GETFL) | O_NONBLOCK);
  assert(e == 0);

  tls_context_t *context;
  e = tls_context_init(&context);
  assert(e == 0);

  tls_t *a;
  e = tls_init(context, on_a_read, on_a_write, &a);
  assert(e == 0);

  e = tls_use_certificate(a, (char *) cert_pem, cert_pem_len);
  assert(e == 0);

  e = tls_use_key(a, (char *) cert_key, cert_key_len);
  assert(e == 0);

  tls_t *b;
  e = tls_init(context, on_b_read, on_b_write, &b);
  assert(e == 0);

  e = tls_accept(a);
  assert(e == 0);

  e = tls_connect(b);
  assert(e == 0);
}
