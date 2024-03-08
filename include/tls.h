#ifndef TLS_H
#define TLS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_context_s tls_context_t;
typedef struct tls_s tls_t;

typedef int (*tls_read_cb)(tls_t *, char *data, int len);
typedef int (*tls_write_cb)(tls_t *, const char *data, int len);

typedef enum {
  tls_ok = 0,
  tls_error = -1,
  tls_eof = -2,
  tls_retry = -3,
} tls_status_t;

int
tls_context_init (tls_context_t **result);

void
tls_context_destroy (tls_context_t *context);

int
tls_init (tls_context_t *context, tls_read_cb read, tls_write_cb write, tls_t **result);

void
tls_destroy (tls_t *tls);

int
tls_use_certificate (tls_t *tls, const char *pem, int len);

int
tls_use_key (tls_t *tls, const char *pem, int len);

int
tls_connect (tls_t *tls);

int
tls_accept (tls_t *tls);

int
tls_read (tls_t *tls, char *data, int len);

int
tls_write (tls_t *tls, const char *data, int len);

int
tls_shutdown (tls_t *tls);

#ifdef __cplusplus
}
#endif

#endif // TLS_H
