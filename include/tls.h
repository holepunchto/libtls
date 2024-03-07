#ifndef TLS_H
#define TLS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_context_s tls_context_t;
typedef struct tls_s tls_t;

int
tls_context_init (tls_context_t **result);

void
tls_context_destroy (tls_context_t *context);

int
tls_init (tls_context_t *context, tls_t **result);

void
tls_destroy (tls_t *tls);

#ifdef __cplusplus
}
#endif

#endif // TLS_H
