/*
 * traffic_meter_user.c - User-space loader for traffic_meter eBPF program.
 * Attaches cgroup/skb programs to the root cgroup to capture all traffic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct traffic_event {
    __u32 uid;
    __u32 bytes;
    __u32 src_ip;
    __u32 dst_ip;
    __u8 direction;
};

struct traffic_event_v6 {
    __u32 uid;
    __u32 bytes;
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u8 direction;
};

struct uid_stats {
    __u32 uid;
    __u64 total_in;
    __u64 total_out;
    struct uid_stats *next;
};

#define HASH_SIZE 1024
static struct uid_stats *uid_hash[HASH_SIZE];

static volatile int exiting = 0;
static const char *g_nic_id = "unknown";

static struct uid_stats *find_or_create_stats(__u32 uid)
{
    unsigned int idx = uid % HASH_SIZE;
    struct uid_stats *s = uid_hash[idx];
    while (s) {
        if (s->uid == uid)
            return s;
        s = s->next;
    }
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->uid = uid;
    s->next = uid_hash[idx];
    uid_hash[idx] = s;
    return s;
}

static void sig_handler(int sig) { exiting = 1; }

static void ip_to_str(__u32 ip, char *buf, size_t buflen)
{
    struct in_addr a = { .s_addr = ip };
    inet_ntop(AF_INET, &a, buf, buflen);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct traffic_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(e->src_ip, src, sizeof(src));
    ip_to_str(e->dst_ip, dst, sizeof(dst));

    struct uid_stats *stats = find_or_create_stats(e->uid);
    if (!stats)
        return 0;

    if (e->direction)
        stats->total_out += e->bytes;
    else
        stats->total_in += e->bytes;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/traffic_user_%s_%u.log", g_nic_id, e->uid);
    FILE *f = fopen(filename, "a");
    if (f) {
        fprintf(f, "%s,%u,%s,%s,%ld.%09ld,%llu,%llu\n",
                e->direction ? "out" : "in", e->bytes, src, dst,
                ts.tv_sec, ts.tv_nsec,
                (unsigned long long)stats->total_in,
                (unsigned long long)stats->total_out);
        fclose(f);
    }
    return 0;
}

static int handle_event_v6(void *ctx, void *data, size_t data_sz)
{
    struct traffic_event_v6 *e = data;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET6, e->dst_ip, dst, sizeof(dst));

    struct uid_stats *stats = find_or_create_stats(e->uid);
    if (!stats)
        return 0;

    if (e->direction)
        stats->total_out += e->bytes;
    else
        stats->total_in += e->bytes;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/traffic_user_%s_%u.log", g_nic_id, e->uid);
    FILE *f = fopen(filename, "a");
    if (f) {
        fprintf(f, "%s,%u,%s,%s,%ld.%09ld,%llu,%llu\n",
                e->direction ? "out" : "in", e->bytes, src, dst,
                ts.tv_sec, ts.tv_nsec,
                (unsigned long long)stats->total_in,
                (unsigned long long)stats->total_out);
        fclose(f);
    }
    return 0;
}

int main(int argc, char **argv)
{
    g_nic_id = (argc > 2) ? argv[2] : "unknown";
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open the cgroup v2 (use argument or default to user.slice for user processes) */
    const char *cgroup_path = (argc > 1) ? argv[1] : "/sys/fs/cgroup/user.slice";
    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        /* Fall back to root cgroup */
        cgroup_path = "/sys/fs/cgroup";
        cgroup_fd = open(cgroup_path, O_RDONLY);
        if (cgroup_fd < 0) {
            perror("open cgroup");
            return 1;
        }
    }
    printf("Using cgroup: %s\n", cgroup_path);

    /* Load BPF object */
    struct bpf_object *obj = bpf_object__open_file("traffic_meter.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        close(cgroup_fd);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Find and attach egress program (IPv4) */
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(obj, "traffic_meter_egress");
    if (!prog_egress) {
        fprintf(stderr, "Failed to find egress program\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_egress_fd = bpf_program__fd(prog_egress);
    if (bpf_prog_attach(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach egress");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Find and attach ingress program (IPv4) */
    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(obj, "traffic_meter_ingress");
    if (!prog_ingress) {
        fprintf(stderr, "Failed to find ingress program\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_ingress_fd = bpf_program__fd(prog_ingress);
    if (bpf_prog_attach(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach ingress");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Find and attach egress program (IPv6) */
    struct bpf_program *prog_egress_v6 = bpf_object__find_program_by_name(obj, "traffic_meter_egress_v6");
    if (!prog_egress_v6) {
        fprintf(stderr, "Failed to find IPv6 egress program\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_egress_v6_fd = bpf_program__fd(prog_egress_v6);
    if (bpf_prog_attach(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach egress v6");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Find and attach ingress program (IPv6) */
    struct bpf_program *prog_ingress_v6 = bpf_object__find_program_by_name(obj, "traffic_meter_ingress_v6");
    if (!prog_ingress_v6) {
        fprintf(stderr, "Failed to find IPv6 ingress program\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_ingress_v6_fd = bpf_program__fd(prog_ingress_v6);
    if (bpf_prog_attach(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach ingress v6");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Set up ring buffers */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_object__find_map_fd_by_name(obj, "events"),
        handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Add IPv6 ring buffer to same ring_buffer manager */
    if (ring_buffer__add(rb, bpf_object__find_map_fd_by_name(obj, "events_v6"),
                         handle_event_v6, NULL) < 0) {
        fprintf(stderr, "Failed to add IPv6 ring buffer\n");
        ring_buffer__free(rb);
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    printf("eBPF traffic meter loaded (cgroup mode, IPv4+IPv6). Press Ctrl+C to exit.\n");
    fflush(stdout);

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    /* Cleanup */
    ring_buffer__free(rb);
    bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach2(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_object__close(obj);
    close(cgroup_fd);

    printf("Detached and exiting.\n");
    return 0;
}
