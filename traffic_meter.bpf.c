/*
 * traffic_meter.bpf.c - eBPF program to meter network traffic per UID.
 * Uses cgroup/skb hooks which have access to socket UID.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Structure stored per UID */
struct traffic_stats {
    __u64 bytes;
    __u32 src_ip;
    __u32 dst_ip;
};

/* Hash map keyed by UID */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} uid_stats_map SEC(".maps");

SEC("cgroup_skb/egress")
int traffic_meter_egress(struct __sk_buff *skb)
{
    __u32 uid = bpf_get_socket_uid(skb);
    __u32 src_ip = 0, dst_ip = 0;

    /* Check for IPv4 by examining first byte of IP header */
    __u8 ip_ver = 0;
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);
    if ((ip_ver >> 4) != 4)
        return 1;

    /* Load src/dst IP from IP header (offset 12 and 16) */
    bpf_skb_load_bytes(skb, 12, &src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &dst_ip, 4);

    struct traffic_stats *val;
    struct traffic_stats zero = {};
    val = bpf_map_lookup_elem(&uid_stats_map, &uid);
    if (!val) {
        zero.src_ip = src_ip;
        zero.dst_ip = dst_ip;
        zero.bytes = skb->len;
        bpf_map_update_elem(&uid_stats_map, &uid, &zero, BPF_ANY);
    } else {
        __sync_fetch_and_add(&val->bytes, skb->len);
        val->src_ip = src_ip;
        val->dst_ip = dst_ip;
    }

    return 1;
}

SEC("cgroup_skb/ingress")
int traffic_meter_ingress(struct __sk_buff *skb)
{
    __u32 uid = bpf_get_socket_uid(skb);
    __u32 src_ip = 0, dst_ip = 0;

    __u8 ip_ver = 0;
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);
    if ((ip_ver >> 4) != 4)
        return 1;

    bpf_skb_load_bytes(skb, 12, &src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &dst_ip, 4);

    struct traffic_stats *val;
    struct traffic_stats zero = {};
    val = bpf_map_lookup_elem(&uid_stats_map, &uid);
    if (!val) {
        zero.src_ip = src_ip;
        zero.dst_ip = dst_ip;
        zero.bytes = skb->len;
        bpf_map_update_elem(&uid_stats_map, &uid, &zero, BPF_ANY);
    } else {
        __sync_fetch_and_add(&val->bytes, skb->len);
        val->src_ip = src_ip;
        val->dst_ip = dst_ip;
    }

    return 1;
}

char _license[] SEC("license") = "GPL";
