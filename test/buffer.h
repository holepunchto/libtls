#ifndef TLS_BUFFER_H
#define TLS_BUFFER_H

#include <stdlib.h>
#include <string.h>

typedef struct tls__buffer_s tls__buffer_t;

struct tls__buffer_s {
  char *data;
  int cap;
  int len;
  int head;
  int tail;
};

static inline int
tls__buffer_init (tls__buffer_t *buffer, int cap) {
  char *data = malloc(cap);

  if (data == NULL) return -1;

  buffer->data = data;
  buffer->cap = cap;
  buffer->len = 0;
  buffer->head = 0;
  buffer->tail = 0;

  return 0;
}

static inline void
tls__buffer_destroy (tls__buffer_t *buffer) {
  free(buffer->data);
}

static inline int
tls__buffer_read (tls__buffer_t *buffer, char *data, int len) {
  if (len >= buffer->len) len = buffer->len;

  if (len <= buffer->cap - buffer->head) {
    memcpy(data, &buffer->data[buffer->head], len);

    buffer->head += len;

    if (buffer->head == buffer->cap) buffer->head = 0;
  } else {
    int fst = buffer->cap - buffer->head;

    memcpy(data, &buffer->data[buffer->head], fst);

    int snd = len - fst;

    memcpy(&data[fst], buffer->data, snd);

    buffer->head = snd;
  }

  buffer->len -= len;

  return len;
}

static inline int
tls__buffer_write (tls__buffer_t *buffer, const char *data, int len) {
  if (len + buffer->len >= buffer->cap) return -1;

  if (len <= buffer->cap - buffer->tail) {
    memcpy(&buffer->data[buffer->tail], data, len);

    buffer->tail += len;

    if (buffer->tail == buffer->cap) buffer->tail = 0;
  } else {
    int fst = buffer->cap - buffer->tail;

    memcpy(&buffer->data[buffer->tail], data, fst);

    int snd = len - fst;

    memcpy(&buffer->data, &data[fst], snd);

    buffer->tail = snd;
  }

  buffer->len += len;

  return len;
}

#endif // TLS_BUFFER_H
