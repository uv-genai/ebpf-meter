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

static volatile int exiting = 0;
static const char *g_nic_id = "unknown";

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

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/traffic_user_%s_%u.log", g_nic_id, e->uid);
    FILE *f = fopen(filename, "a");
    if (f) {
        fprintf(f, "%s,%u,%s,%s,%ld.%09ld\n",
                e->direction ? "out" : "in", e->bytes, src, dst,
                ts.tv_sec, ts.tv_nsec);
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

    /* Find and attach egress program */
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(obj, "traffic_meter_egress");
    if (!prog_egress) {
        fprintf(stderr, "Failed to find egress program\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_egress_fd = bpf_program__fd(prog_egress);
    if (bpf_prog_attach(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0) < 0) {
        perror("bpf_prog_attach egress");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Find and attach ingress program */
    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(obj, "traffic_meter_ingress");
    if (!prog_ingress) {
        fprintf(stderr, "Failed to find ingress program\n");
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_ingress_fd = bpf_program__fd(prog_ingress);
    if (bpf_prog_attach(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, 0) < 0) {
        perror("bpf_prog_attach ingress");
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /* Set up ring buffer */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_object__find_map_fd_by_name(obj, "events"),
        handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    printf("eBPF traffic meter loaded (cgroup mode). Press Ctrl+C to exit.\n");
    fflush(stdout);

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    /* Cleanup */
    ring_buffer__free(rb);
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_object__close(obj);
    close(cgroup_fd);

    printf("Detached and exiting.\n");
    return 0;
}
