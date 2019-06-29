#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <linux/tcp.h>

#include "h2o.h"

#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#endif

struct tcp_option {
    uint32_t opt_code;
    uint32_t opt_val;
};

struct exported_tcp {
    union {
        struct sockaddr raw;
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } sock_addr, peer_addr;
    uint32_t seq;
    uint32_t ack;
    uint32_t snd_wl1;
    uint32_t snd_wnd;
    uint32_t max_window;
    uint32_t rcv_wnd;
    uint32_t rcv_wup;
    uint32_t sack_perm;
    uint32_t mss;
    uint32_t snd_wscale;
    uint32_t rcv_wscale;
    uint32_t timestamp;
};

struct tcp_info_sub {
  uint8_t tcpi_state;
  uint8_t tcpi_ca_state;
  uint8_t tcpi_retransmits;
  uint8_t tcpi_probes;
  uint8_t tcpi_backoff;
  uint8_t tcpi_options;
  uint8_t tcpi_snd_wscale : 4;
  uint8_t tcpi_rcv_wscale : 4;
};

static int
tcp_repair_start(int sock)
{
  int error, opt = 1;
  error = setsockopt(sock, IPPROTO_TCP, TCP_REPAIR, &opt, sizeof(opt));
  if (error) {
    return errno;
  }
  return 0;
}

static int
tcp_repair_done(int sock)
{
  int error, opt = -1;
  error = setsockopt(sock, IPPROTO_TCP, TCP_REPAIR, &opt, sizeof(opt));
  if (error) {
    return errno;
  }
  return 0;
}

static int
tcp_is_established(int sock, struct tcp_info_sub *info)
{
  int error;
  socklen_t opt_len = sizeof(*info);

  error = getsockopt(sock, IPPROTO_TCP, TCP_INFO, info, &opt_len);
  if (error == -1 || opt_len != sizeof(*info)) {
    return errno;
  }

  if (info->tcpi_state != TCP_ESTABLISHED) {
    return EINVAL;
  }

  return 0;
}

static int
tcp_get_options(int sock, struct exported_tcp *ex, struct tcp_info_sub *info)
{
  int error;
  uint32_t mss;
  uint32_t timestamp;
  socklen_t opt_len = sizeof(mss);

  if (info->tcpi_options & TCPI_OPT_SACK) {
    ex->sack_perm = 1;
  } else {
    ex->sack_perm = 0;
  }

  error = getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, &opt_len);
  if (error == -1) {
    return errno;
  }

  ex->mss = mss;
  ex->snd_wscale = info->tcpi_snd_wscale;
  ex->rcv_wscale = info->tcpi_rcv_wscale;

  opt_len = sizeof(timestamp);
  error = getsockopt(sock, IPPROTO_TCP, TCP_TIMESTAMP, &timestamp, &opt_len);
  if (error == -1) {
    return errno;
  }

  ex->timestamp = timestamp;

  return 0;
}

#ifndef TCPOPT_MSS
#define TCPOPT_MSS 2
#endif

#ifndef TCPOPT_WINDOW
#define TCPOPT_WINDOW 3
#endif

#ifndef TCPOPT_SACK_PERM
#define TCPOPT_SACK_PERM 4
#endif

#ifndef TCPOPT_TIMESTAMP
#define TCPOPT_TIMESTAMP 8
#endif

static int
tcp_set_options(int sock, struct exported_tcp *ex)
{
  int error, nopt = 0;
  struct tcp_repair_opt opts[4];

  if (ex->sack_perm == 1) {
      opts[nopt].opt_code = TCPOPT_SACK_PERM;
      opts[nopt].opt_val = 0;
      nopt++;
  }

  opts[nopt].opt_code = TCPOPT_WINDOW;
  opts[nopt].opt_val = ex->snd_wscale + (ex->rcv_wscale << 16);
  nopt++;

  if (ex->timestamp != 0) {
      opts[nopt].opt_code = TCPOPT_TIMESTAMP;
      opts[nopt].opt_val = 0;
      nopt++;
  }

  opts[nopt].opt_code = TCPOPT_MSS;
  opts[nopt].opt_val = ex->mss;
  nopt++;

  error = setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_OPTIONS, opts,
                     sizeof(struct tcp_repair_opt) * nopt);
  if (error == -1) {
    return errno;
  }

  if (ex->timestamp != 0) {
      uint32_t tstamp = ex->timestamp;
      error = setsockopt(sock, IPPROTO_TCP, TCP_TIMESTAMP, &tstamp, sizeof(tstamp));
      if (error == -1) {
        return errno;
      }
  }

  return 0;
}

static int
tcp_get_window(int sock, struct exported_tcp *ex)
{
  int error;
  struct tcp_repair_window window;
  socklen_t slen = sizeof(struct tcp_repair_window);

  error = getsockopt(sock, IPPROTO_TCP, TCP_REPAIR_WINDOW, &window, &slen);
  if (error) {
    return errno;
  }

  ex->snd_wl1 = window.snd_wl1;
  ex->snd_wnd = window.snd_wnd;
  ex->max_window = window.max_window;
  ex->rcv_wnd = window.rcv_wnd;
  ex->rcv_wup = window.rcv_wup;

  return 0;
}

static int
tcp_set_window(int sock, struct exported_tcp *ex)
{
  int error;
  struct tcp_repair_window window;

  window.snd_wl1 = ex->snd_wl1;
  window.snd_wnd = ex->snd_wnd;
  window.max_window = ex->max_window;
  window.rcv_wnd = ex->rcv_wnd;
  window.rcv_wup = ex->rcv_wup;
  error =
      setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_WINDOW, &window, sizeof(window));
  if (error) {
    return errno;
  }

  return 0;
}

static int
tcp_get_addr(int sock, struct exported_tcp *ex)
{
  int error;
  socklen_t len;

  len = sizeof(ex->sock_addr);
  error = getsockname(sock, &ex->sock_addr.raw, &len);
  if (error == -1) {
    return errno;
  }

  len = sizeof(ex->peer_addr);
  error = getpeername(sock, &ex->peer_addr.raw, &len);
  if (error == -1) {
    return errno;
  }

  return 0;
}

static int
tcp_set_addr(int sock, struct exported_tcp *ex)
{
  int error;
  socklen_t len;

  if (ex->sock_addr.raw.sa_family == AF_INET) {
      len = sizeof(ex->sock_addr.v4);
  } else if (ex->sock_addr.raw.sa_family == AF_INET6) {
      len = sizeof(ex->sock_addr.v6);
  } else {
      return EINVAL;
  }

  error = bind(sock, &ex->sock_addr.raw, len);
  if (error) {
    return errno;
  }

  if (ex->peer_addr.raw.sa_family == AF_INET) {
      len = sizeof(ex->peer_addr.v4);
  } else if (ex->peer_addr.raw.sa_family == AF_INET6) {
      len = sizeof(ex->peer_addr.v6);
  } else {
      return EINVAL;
  }

  error = connect(sock, &ex->sock_addr.raw, len);
  if (error) {
    return errno;
  }

  return 0;
}

static int
tcp_get_seq(int sock, int queue, struct exported_tcp *ex)
{
  int error;
  uint32_t *seq;
  socklen_t len;

  if (queue == TCP_SEND_QUEUE) {
    seq = &ex->seq;
  } else {
    seq = &ex->ack;
  }

  error =
      setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
  if (error == -1) {
    return errno;
  }

  len = sizeof(*seq);

  error = getsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ, seq, &len);
  if (error == -1) {
    return errno;
  }

  return 0;
}

static int
tcp_set_seq(int sock, int queue, struct exported_tcp *ex)
{
  int error;
  uint32_t seq;

  if (queue == TCP_SEND_QUEUE) {
    seq = ex->seq;
  } else {
    seq = ex->ack;
  }

  error =
      setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
  if (error == -1) {
    return errno;
  }

  error = setsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq));
  if (error == -1) {
    return errno;
  }

  return 0;
}

static int
tcp_export(int sock, struct exported_tcp *ex)
{
  int error;
  struct tcp_info_sub info;

  if (ex == NULL) {
    return EINVAL;
  }

#define TRY(_funccall, _label)                                                 \
  if ((error = _funccall) != 0) {                                              \
    printf("trying" #_funccall "\n");                                          \
    goto _label;                                                               \
  }

  TRY(tcp_repair_start(sock), err0);
  TRY(tcp_is_established(sock, &info), err1);
  TRY(tcp_get_seq(sock, TCP_SEND_QUEUE, ex), err1);
  TRY(tcp_get_seq(sock, TCP_RECV_QUEUE, ex), err1);
  TRY(tcp_get_options(sock, ex, &info), err1);
  TRY(tcp_get_window(sock, ex), err1);
  TRY(tcp_get_addr(sock, ex), err1);

#undef TRY

  return 0;

err1:
  assert(tcp_repair_done(sock) == 0);
err0:
  return error;
}

static int
tcp_import(int sock, struct exported_tcp *ex)
{
  int error;

  if (ex == NULL) {
    return EINVAL;
  }

#define TRY(_funccall, _label)                                                 \
  if ((error = _funccall) != 0) {                                              \
    goto _label;                                                               \
  }

  TRY(tcp_repair_start(sock), err0);
  TRY(tcp_set_seq(sock, TCP_SEND_QUEUE, ex), err1);
  TRY(tcp_set_seq(sock, TCP_RECV_QUEUE, ex), err1);
  TRY(tcp_set_addr(sock, ex), err1);
  TRY(tcp_set_options(sock, ex), err1);
  TRY(tcp_set_window(sock, ex), err1);
  TRY(tcp_repair_done(sock), err1);

#undef TRY

  return 0;

err1:
  assert(tcp_repair_done(sock) == 0);
err0:
  return error;
}

// base64 encoder/decoder from https://github.com/littlstar/b64.c

static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

char *
base64_encode(const unsigned char *src, size_t len, size_t *encsize) {
  int i = 0;
  int j = 0;
  char *enc = NULL;
  size_t size = 0;
  unsigned char buf[4];
  unsigned char tmp[3];

  enc = (char *) malloc(len * 2);
  if (NULL == enc) { return NULL; }

  while (len--) {
    tmp[i++] = *(src++);

    if (3 == i) {
      buf[0] = (tmp[0] & 0xfc) >> 2;
      buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
      buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
      buf[3] = tmp[2] & 0x3f;

      for (i = 0; i < 4; ++i) {
        enc[size++] = b64_table[buf[i]];
      }

      i = 0;
    }
  }

  if (i > 0) {
    for (j = i; j < 3; ++j) {
      tmp[j] = '\0';
    }

    buf[0] = (tmp[0] & 0xfc) >> 2;
    buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
    buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
    buf[3] = tmp[2] & 0x3f;

    for (j = 0; (j < i + 1); ++j) {
      enc[size++] = b64_table[buf[j]];
    }

    while ((i++ < 3)) {
      enc[size++] = '=';
    }
  }

  enc[size] = '\0';

  if (encsize != NULL) {
      *encsize = size;
  }

  return enc;
}

unsigned char *
b64_decode(const char *src, size_t len, size_t *decsize) {
  int i = 0;
  int j = 0;
  int l = 0;
  size_t size = 0;
  unsigned char *dec = NULL;
  unsigned char buf[3];
  unsigned char tmp[4];

  dec = (unsigned char *)malloc(len);
  if (NULL == dec) { return NULL; }

  while (len--) {
    if ('=' == src[j]) { break; }
    if (!(isalnum(src[j]) || '+' == src[j] || '/' == src[j])) { break; }

    tmp[i++] = src[j++];

    if (4 == i) {
      for (i = 0; i < 4; ++i) {
        for (l = 0; l < 64; ++l) {
          if (tmp[i] == b64_table[l]) {
            tmp[i] = l;
            break;
          }
        }
      }

      buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
      buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
      buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

      if (dec != NULL){
        for (i = 0; i < 3; ++i) {
          dec[size++] = buf[i];
        }
      } else {
        return NULL;
      }

      i = 0;
    }
  }

  if (i > 0) {
    for (j = i; j < 4; ++j) {
      tmp[j] = '\0';
    }

    for (j = 0; j < 4; ++j) {
        for (l = 0; l < 64; ++l) {
          if (tmp[j] == b64_table[l]) {
            tmp[j] = l;
            break;
          }
        }
    }

    buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
    buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
    buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

    if (dec != NULL){
      for (j = 0; (j < i - 1); ++j) {
        dec[size++] = buf[j];
      }
    } else {
      return NULL;
    }
  }

  if (dec != NULL){
    dec[size] = '\0';
  } else {
    return NULL;
  }

  if (decsize != NULL) {
    *decsize = size;
  }

  return dec;
}

void
h2o_add_handoff_header(h2o_req_t *req, h2o_headers_t *headers)
{
    int error, fd;
    h2o_socket_t *sock;
    h2o_iovec_t ex_b64;
    struct exported_tcp ex;

    if (req->version >= 0x200) {
        h2o_req_log_error(req, "lib/core/handoff.c", "%s", "handoff is not supported on HTTP2");
        return;
    }

    sock = req->conn->callbacks->get_socket(req->conn);

    fd = h2o_socket_get_fd(sock);
    if (fd == -1) {
        return;
    }

    error = tcp_export(fd, &ex);
    if (error != 0) {
        printf("%s\n", strerror(error));
        return;
    }

    ex_b64.base = base64_encode((const unsigned char *)&ex, sizeof(ex), &ex_b64.len);
    if (ex_b64.base == NULL) {
        printf("base64_encode failed\n");
        return;
    }

    h2o_add_header_by_str(&req->pool, headers, "x-flextream-info-tcp",
            sizeof("x-flextream-info-tcp"), 0, NULL, ex_b64.base, ex_b64.len);
}

/*
void
h2o_read_handoff_header(h2o_req_t *req, h2o_headers_t *headers)
{
    int error, fd, id;
    ssize_t cursor;
    h2o_header_t *slot;
    h2o_socket_t *old_sock, *new_sock;
    h2o_socket_export_t ex_sock;

    cursor = h2o_find_header_by_str(headers, "x-flextream-info-tcp",
            sizeof("x-flextream-info-tcp"), 0);

    slot = headers + cursor;

    struct exported_tcp *ex =
        (struct exported_tcp *)base64_decode(slot->value.base, slot->value.len);
    if (ex == NULL) {
        // error
        return;
    }

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        // error
        return;
    }

    error = tcp_import(fd, ex);
    if (error != 0) {
        printf("%s\n", strerror(error));
        return;
    }

    ex_sock.fd = fd;
    ex_sock.ssl = NULL;
    ex_sock.input = (h2o_buffer_t *)h2o_mem_alloc(sizeof(ex_sock.input));

    new_sock = h2o_socket_import(req->conn->ctx->loop, &ex_sock);
    old_sock = req->conn->callbacks->swap_socket(new_sock);
}
*/
