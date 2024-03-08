#include "buffer.h"
#include "fixtures/cert.crt.h"
#include "fixtures/cert.key.h"

#include <assert.h>
#include <tls.h>

static tls__buffer_t a_buf;
static tls__buffer_t b_buf;

static int
on_a_read (tls_t *tls, char *data, int len) {
  int res = tls__buffer_read(&a_buf, data, len);
  if (res == 0) return tls_retry;
  return res;
}

static int
on_a_write (tls_t *tls, const char *data, int len) {
  int res = tls__buffer_write(&b_buf, data, len);
  if (res == -1) return tls_retry;
  return res;
}

static int
on_b_read (tls_t *tls, char *data, int len) {
  int res = tls__buffer_read(&b_buf, data, len);
  if (res == 0) return tls_retry;
  return res;
}

static int
on_b_write (tls_t *tls, const char *data, int len) {
  int res = tls__buffer_write(&a_buf, data, len);
  if (res == -1) return tls_retry;
  return res;
}

int
main () {
  int e;

  e = tls__buffer_init(&a_buf, 65536);
  assert(e == 0);

  e = tls__buffer_init(&b_buf, 65536);
  assert(e == 0);

  tls_context_t *context;
  e = tls_context_init(&context);
  assert(e == 0);

  tls_t *a;
  e = tls_init(context, on_a_read, on_a_write, &a);
  assert(e == 0);

  e = tls_use_certificate(a, (char *) cert_crt, cert_crt_len);
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

  e = tls_shutdown(a);
  assert(e == 0);

  e = tls_shutdown(b);
  assert(e == 0);

  tls_destroy(a);
  tls_destroy(b);

  tls_context_destroy(context);

  tls__buffer_destroy(&a_buf);
  tls__buffer_destroy(&b_buf);
}
