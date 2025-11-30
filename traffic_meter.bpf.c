/*
 * traffic_meter.bpf.c - eBPF program to meter network traffic per UID.
 * Uses cgroup/skb hooks which have access to socket UID.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Event structure sent to user space */
struct traffic_event {
    __u32 uid;
    __u32 bytes;
    __u32 src_ip;
    __u32 dst_ip;
    __u8 direction; /* 0 = ingress (in), 1 = egress (out) */
};

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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

char _license[] SEC("license") = "GPL";
