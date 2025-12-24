//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

struct event {
  u32 pid;
  u32 uid;
  u16 sport;
  u16 dport;
  u8 family;
  u8 action;  // 1=connect, 2=close
  u8 state;   // TCP state
  u8 network; // 0 = tcp, 1 = udp
  u8 _pad[2]; // padding for alignment
  u8 saddr[16];
  u8 daddr[16];
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int handle_sock(struct sock *sk, u8 action,
                                       u8 require_state) {
  u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
  if (require_state != 0 && state != require_state)
    return 0;

  struct event *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->state = state;
  e->network = 0;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->action = action;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  e->family = family;

  if (family == AF_INET) {
    __builtin_memset(e->saddr, 0, 16);
    __builtin_memset(e->daddr, 0, 16);

    u32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    *(u32 *)&e->saddr[0] = s;
    *(u32 *)&e->daddr[0] = d;
  } else if (family == AF_INET6) {
    BPF_CORE_READ_INTO(&e->saddr, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
  }

  e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) { return handle_sock(sk, 1, 2); }

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk) { return handle_sock(sk, 2, 8); }

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  struct sock *sk = (struct sock *)ctx->skaddr;
  if (!sk)
    return 0;

  // TCP_ESTABLISHED = 1
  if (ctx->newstate != 1)
    return 0;

  struct event *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->state = ctx->newstate;
  e->action = 1;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  e->family = family;

  if (family == 2) { // AF_INET
    BPF_CORE_READ_INTO(&e->saddr[0], sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr[0], sk, __sk_common.skc_daddr);
  } else if (family == 10) { // AF_INET6
    BPF_CORE_READ_INTO(&e->saddr, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
  }

  e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("kprobe/udp_bind")
int BPF_PROG(udp_bind, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
  u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET && family != AF_INET6)
    return 0;

  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->family = family;
  e->network = 1;
  e->action = 1;
  e->state = BPF_CORE_READ(sk, __sk_common.skc_state);

  e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("kprobe/inet_bind")
int BPF_PROG(inet_bind, struct socket *sock, struct sockaddr *uaddr,
             int addr_len) {
  u16 protocol = BPF_CORE_READ(sock, sk, sk_protocol);

  if (protocol != 17) {
    return 0;
  }

  struct event *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->action = 1; // UDP Bind

  if (addr_len >= sizeof(struct sockaddr_in)) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)uaddr;
    u16 sport;
    bpf_probe_read_kernel(&sport, sizeof(sport), &addr4->sin_port);
    e->sport = bpf_ntohs(sport);
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  u16 protocol = BPF_CORE_READ(sock, sk, sk_protocol);
  if (protocol != 17) {
    return 0;
  }

  struct event *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->network = 1;
  e->action = 1; // UDP Bind
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  u16 family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
  e->family = family;

  if (family == AF_INET) { // IPv4
    struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
    u16 port;
    bpf_probe_read_kernel(&port, sizeof(port), &addr4->sin_port);
    e->sport = bpf_ntohs(port);
  } else if (family == AF_INET6) { // IPv6
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
    u16 port;
    bpf_probe_read_kernel(&port, sizeof(port), &addr6->sin6_port);
    e->sport = bpf_ntohs(port);
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_exit, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret != 0)
    return 0;

  // AF_INET = 2, AF_INET6 = 10
  u16 family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);

  // only UDP
  u16 protocol = BPF_CORE_READ(sock, sk, sk_protocol);
  if (protocol != 17)
    return 0;

  struct event *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->network = 1;
  e->family = family;
  e->action = 1; // UDP Bind

  u16 sport = BPF_CORE_READ(sock, sk, __sk_common.skc_num);
  e->sport = sport;

  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
