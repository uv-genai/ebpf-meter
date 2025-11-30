/*
 * traffic_meter.bpf.c - eBPF program to meter network traffic per UID.
 * Uses cgroup/skb hooks which have access to socket UID.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Event structure sent to user space for IPv4 */
struct traffic_event {
    __u32 uid;
    __u32 bytes;
    __u32 src_ip;
    __u32 dst_ip;
    __u8 direction; /* 0 = ingress (in), 1 = egress (out) */
};

/* Event structure sent to user space for IPv6 */
struct traffic_event_v6 {
    __u32 uid;
    __u32 bytes;
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u8 direction; /* 0 = ingress (in), 1 = egress (out) */
};

/* Ring buffer for IPv4 events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Ring buffer for IPv6 events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_v6 SEC(".maps");

SEC("cgroup_skb/egress")
int traffic_meter_egress(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);
    if ((ip_ver >> 4) != 4)
        return 1;

    struct traffic_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;

    e->uid = bpf_get_socket_uid(skb);
    e->bytes = skb->len;
    e->direction = 1; /* egress = out */
    bpf_skb_load_bytes(skb, 12, &e->src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &e->dst_ip, 4);

    bpf_ringbuf_submit(e, 0);
    return 1;
}

SEC("cgroup_skb/ingress")
int traffic_meter_ingress(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);
    if ((ip_ver >> 4) != 4)
        return 1;

    struct traffic_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;

    e->uid = bpf_get_socket_uid(skb);
    e->bytes = skb->len;
    e->direction = 0; /* ingress = in */
    bpf_skb_load_bytes(skb, 12, &e->src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &e->dst_ip, 4);

    bpf_ringbuf_submit(e, 0);
    return 1;
}

/* IPv6 egress hook */
SEC("cgroup_skb/egress")
int traffic_meter_egress_v6(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);
    if ((ip_ver >> 4) != 6)
        return 1;

    struct traffic_event_v6 *e = bpf_ringbuf_reserve(&events_v6, sizeof(*e), 0);
    if (!e)
        return 1;

    e->uid = bpf_get_socket_uid(skb);
    e->bytes = skb->len;
    e->direction = 1; /* egress = out */
    bpf_skb_load_bytes(skb, 8, &e->src_ip, 16);
    bpf_skb_load_bytes(skb, 24, &e->dst_ip, 16);

    bpf_ringbuf_submit(e, 0);
    return 1;
}

/* IPv6 ingress hook */
SEC("cgroup_skb/ingress")
int traffic_meter_ingress_v6(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);
    if ((ip_ver >> 4) != 6)
        return 1;

    struct traffic_event_v6 *e = bpf_ringbuf_reserve(&events_v6, sizeof(*e), 0);
    if (!e)
        return 1;

    e->uid = bpf_get_socket_uid(skb);
    e->bytes = skb->len;
    e->direction = 0; /* ingress = in */
    bpf_skb_load_bytes(skb, 8, &e->src_ip, 16);
    bpf_skb_load_bytes(skb, 24, &e->dst_ip, 16);

    bpf_ringbuf_submit(e, 0);
    return 1;
}

char _license[] SEC("license") = "GPL";
