/*
 * traffic_meter.bpf.c - eBPF program to meter network traffic per UID.
 *
 * This program attaches to cgroup_skb hooks to capture all IPv4 and IPv6
 * network traffic. It uses cgroup hooks (rather than XDP) because they
 * provide access to socket information, including the UID of the process
 * that owns the socket.
 *
 * For each packet, we extract:
 *   - UID of the socket owner
 *   - Packet size in bytes
 *   - Source and destination IP addresses (IPv4 or IPv6)
 *   - Direction (ingress or egress)
 *
 * Events are sent to user space via ring buffers (separate for IPv4/IPv6)
 * for real-time processing.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * IPv4 event structure sent to user space via ring buffer.
 * This is a per-packet event containing all relevant traffic metadata.
 */
struct traffic_event {
    __u32 uid;       /* UID of the process owning the socket */
    __u32 bytes;     /* Packet size in bytes */
    __u32 src_ip;    /* Source IPv4 address (network byte order) */
    __u32 dst_ip;    /* Destination IPv4 address (network byte order) */
    __u8 direction;  /* Traffic direction: 0 = ingress (in), 1 = egress (out) */
};

/*
 * IPv6 event structure sent to user space via ring buffer.
 * Uses 16-byte arrays for 128-bit IPv6 addresses.
 */
struct traffic_event_v6 {
    __u32 uid;        /* UID of the process owning the socket */
    __u32 bytes;      /* Packet size in bytes */
    __u8 src_ip[16];  /* Source IPv6 address (network byte order) */
    __u8 dst_ip[16];  /* Destination IPv6 address (network byte order) */
    __u8 direction;   /* Traffic direction: 0 = ingress (in), 1 = egress (out) */
};

/*
 * Ring buffer map for IPv4 events.
 * Size is 256KB which can hold thousands of events before overflow.
 * User space must poll frequently enough to prevent event loss.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB ring buffer */
} events SEC(".maps");

/*
 * Ring buffer map for IPv6 events.
 * Separate from IPv4 to allow different event structures and
 * independent consumption rates.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB ring buffer */
} events_v6 SEC(".maps");

/*
 * traffic_meter_egress - Capture outgoing (egress) IPv4 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every outgoing packet in the attached cgroup.
 * It filters for IPv4 packets, extracts metadata, and sends an event to
 * user space via the ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/egress")
int traffic_meter_egress(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv4 packets (version == 4) */
    if ((ip_ver >> 4) != 4)
        return 1;

    /* Reserve space in ring buffer for our event */
    struct traffic_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as egress (outgoing) traffic */
    e->direction = 1;

    /*
     * Extract source and destination IPs from IPv4 header.
     * IPv4 header layout:
     *   Offset 12: Source IP (4 bytes)
     *   Offset 16: Destination IP (4 bytes)
     */
    bpf_skb_load_bytes(skb, 12, &e->src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &e->dst_ip, 4);

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/*
 * traffic_meter_ingress - Capture incoming (ingress) IPv4 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every incoming packet in the attached cgroup.
 * It filters for IPv4 packets, extracts metadata, and sends an event to
 * user space via the ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/ingress")
int traffic_meter_ingress(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv4 packets (version == 4) */
    if ((ip_ver >> 4) != 4)
        return 1;

    /* Reserve space in ring buffer for our event */
    struct traffic_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as ingress (incoming) traffic */
    e->direction = 0;

    /*
     * Extract source and destination IPs from IPv4 header.
     * IPv4 header layout:
     *   Offset 12: Source IP (4 bytes)
     *   Offset 16: Destination IP (4 bytes)
     */
    bpf_skb_load_bytes(skb, 12, &e->src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &e->dst_ip, 4);

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/*
 * traffic_meter_egress_v6 - Capture outgoing (egress) IPv6 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every outgoing packet in the attached cgroup.
 * It filters for IPv6 packets, extracts metadata, and sends an event to
 * user space via the IPv6 ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/egress")
int traffic_meter_egress_v6(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv6 packets (version == 6) */
    if ((ip_ver >> 4) != 6)
        return 1;

    /* Reserve space in IPv6 ring buffer for our event */
    struct traffic_event_v6 *e = bpf_ringbuf_reserve(&events_v6, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as egress (outgoing) traffic */
    e->direction = 1;

    /*
     * Extract source and destination IPs from IPv6 header.
     * IPv6 header layout:
     *   Offset 8: Source IP (16 bytes)
     *   Offset 24: Destination IP (16 bytes)
     */
    bpf_skb_load_bytes(skb, 8, &e->src_ip, 16);
    bpf_skb_load_bytes(skb, 24, &e->dst_ip, 16);

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/*
 * traffic_meter_ingress_v6 - Capture incoming (ingress) IPv6 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every incoming packet in the attached cgroup.
 * It filters for IPv6 packets, extracts metadata, and sends an event to
 * user space via the IPv6 ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/ingress")
int traffic_meter_ingress_v6(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv6 packets (version == 6) */
    if ((ip_ver >> 4) != 6)
        return 1;

    /* Reserve space in IPv6 ring buffer for our event */
    struct traffic_event_v6 *e = bpf_ringbuf_reserve(&events_v6, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as ingress (incoming) traffic */
    e->direction = 0;

    /*
     * Extract source and destination IPs from IPv6 header.
     * IPv6 header layout:
     *   Offset 8: Source IP (16 bytes)
     *   Offset 24: Destination IP (16 bytes)
     */
    bpf_skb_load_bytes(skb, 8, &e->src_ip, 16);
    bpf_skb_load_bytes(skb, 24, &e->dst_ip, 16);

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/* GPL license required for using bpf_get_socket_uid and other GPL-only helpers */
char _license[] SEC("license") = "GPL";
