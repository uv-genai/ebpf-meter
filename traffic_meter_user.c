/*
 * traffic_meter_user.c - User-space loader for traffic_meter eBPF program.
 *
 * This program:
 *   1. Loads the compiled eBPF object file (traffic_meter.bpf.o)
 *   2. Attaches the eBPF programs to a cgroup for traffic monitoring
 *   3. Polls the ring buffer for traffic events from the kernel
 *   4. Writes per-packet CSV logs to per-user files
 *
 * Usage: sudo ./traffic_meter_user [cgroup_path] [nic_id]
 *
 * Output files: /tmp/traffic_user_<nic_id>_<uid>.log
 * CSV format: direction,bytes,src_ip,dst_ip,timestamp,total_in,total_out
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

/*
 * Traffic event structure - must match the kernel-side definition exactly.
 * Received from the eBPF ring buffer for each captured packet.
 */
struct traffic_event {
    __u32 uid;       /* UID of the process owning the socket */
    __u32 bytes;     /* Packet size in bytes */
    __u32 src_ip;    /* Source IPv4 address (network byte order) */
    __u32 dst_ip;    /* Destination IPv4 address (network byte order) */
    __u8 direction;  /* 0 = ingress (in), 1 = egress (out) */
};

/*
 * Per-UID statistics structure for tracking cumulative byte counts.
 * Stored in a hash table keyed by UID for O(1) lookup.
 */
struct uid_stats {
    __u32 uid;              /* User ID */
    __u64 total_in;         /* Cumulative bytes received */
    __u64 total_out;        /* Cumulative bytes sent */
    struct uid_stats *next; /* Next entry in hash bucket (chaining) */
};

/* Hash table size for UID stats - should be power of 2 for efficient modulo */
#define HASH_SIZE 1024

/* Global hash table for per-UID cumulative statistics */
static struct uid_stats *uid_hash[HASH_SIZE];

/* Flag set by signal handler to trigger graceful shutdown */
static volatile int exiting = 0;

/* NIC identifier for log filenames (from command line) */
static const char *g_nic_id = "unknown";

/*
 * find_or_create_stats - Get or create stats entry for a UID.
 *
 * @uid: User ID to look up
 *
 * Uses a simple hash table with chaining for collision resolution.
 * Creates a new entry if the UID is not found.
 *
 * Returns: Pointer to uid_stats structure, or NULL on allocation failure
 */
static struct uid_stats *find_or_create_stats(__u32 uid)
{
    /* Hash UID to get bucket index */
    unsigned int idx = uid % HASH_SIZE;

    /* Search the chain for existing entry */
    struct uid_stats *s = uid_hash[idx];
    while (s) {
        if (s->uid == uid)
            return s;
        s = s->next;
    }

    /* Not found - create new entry */
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    /* Initialize and insert at head of chain */
    s->uid = uid;
    s->next = uid_hash[idx];
    uid_hash[idx] = s;

    return s;
}

/*
 * sig_handler - Signal handler for graceful shutdown.
 *
 * @sig: Signal number (unused)
 *
 * Sets the exiting flag to break the main polling loop.
 */
static void sig_handler(int sig)
{
    (void)sig;  /* Suppress unused parameter warning */
    exiting = 1;
}

/*
 * ip_to_str - Convert IPv4 address to string representation.
 *
 * @ip: IPv4 address in network byte order
 * @buf: Output buffer for the string
 * @buflen: Size of output buffer (should be >= INET_ADDRSTRLEN)
 */
static void ip_to_str(__u32 ip, char *buf, size_t buflen)
{
    struct in_addr a = { .s_addr = ip };
    inet_ntop(AF_INET, &a, buf, buflen);
}

/*
 * handle_event - Ring buffer callback for processing traffic events.
 *
 * @ctx: User context (unused)
 * @data: Pointer to traffic_event structure from kernel
 * @data_sz: Size of data (unused, we know the structure size)
 *
 * This function is called by ring_buffer__poll() for each event.
 * It updates cumulative statistics and writes a CSV line to the
 * appropriate per-user log file.
 *
 * Returns: 0 to continue processing events
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;      /* Suppress unused parameter warning */
    (void)data_sz;  /* Suppress unused parameter warning */

    struct traffic_event *e = data;

    /* Convert IP addresses to human-readable strings */
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(e->src_ip, src, sizeof(src));
    ip_to_str(e->dst_ip, dst, sizeof(dst));

    /* Get or create cumulative stats for this UID */
    struct uid_stats *stats = find_or_create_stats(e->uid);
    if (!stats)
        return 0;  /* Allocation failed, skip this event */

    /* Update cumulative byte counters based on direction */
    if (e->direction)
        stats->total_out += e->bytes;
    else
        stats->total_in += e->bytes;

    /* Get current timestamp with nanosecond precision */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    /* Build filename: /tmp/traffic_user_<nic_id>_<uid>.log */
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/traffic_user_%s_%u.log",
             g_nic_id, e->uid);

    /* Append CSV line to the log file */
    FILE *f = fopen(filename, "a");
    if (f) {
        /*
         * CSV format:
         *   direction,bytes,src_ip,dst_ip,timestamp,total_in,total_out
         *
         * Example:
         *   out,1500,192.168.1.100,8.8.8.8,1732985432.123456789,0,1500
         */
        fprintf(f, "%s,%u,%s,%s,%ld.%09ld,%llu,%llu\n",
                e->direction ? "out" : "in",
                e->bytes,
                src, dst,
                ts.tv_sec, ts.tv_nsec,
                (unsigned long long)stats->total_in,
                (unsigned long long)stats->total_out);
        fclose(f);
    }

    return 0;
}

/*
 * main - Program entry point.
 *
 * @argc: Argument count
 * @argv: Argument vector
 *        argv[1] = cgroup path (optional, defaults to /sys/fs/cgroup/user.slice)
 *        argv[2] = NIC identifier for log filenames (optional, defaults to "unknown")
 *
 * Returns: 0 on success, 1 on error
 */
int main(int argc, char **argv)
{
    /* Parse optional NIC identifier from command line */
    g_nic_id = (argc > 2) ? argv[2] : "unknown";

    /*
     * Increase RLIMIT_MEMLOCK to allow BPF maps to be locked in memory.
     * Required for ring buffers and other BPF map types.
     */
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, sig_handler);   /* Ctrl+C */
    signal(SIGTERM, sig_handler);  /* kill command */

    /*
     * Open the cgroup v2 directory.
     * We attach BPF programs to this cgroup to monitor its network traffic.
     * Default to user.slice which contains user processes.
     */
    const char *cgroup_path = (argc > 1 && argv[1][0] != '\0')
                              ? argv[1]
                              : "/sys/fs/cgroup/user.slice";
    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        /* Fall back to root cgroup if user.slice doesn't exist */
        cgroup_path = "/sys/fs/cgroup";
        cgroup_fd = open(cgroup_path, O_RDONLY);
        if (cgroup_fd < 0) {
            perror("open cgroup");
            return 1;
        }
    }
    printf("Using cgroup: %s\n", cgroup_path);

    /*
     * Load the compiled BPF object file.
     * This contains the BPF programs and maps defined in traffic_meter.bpf.c
     */
    struct bpf_object *obj = bpf_object__open_file("traffic_meter.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        close(cgroup_fd);
        return 1;
    }

    /* Load BPF programs and maps into the kernel */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object into kernel\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /*
     * Find and attach the egress (outgoing traffic) BPF program.
     * BPF_CGROUP_INET_EGRESS hook is called for all outgoing packets.
     */
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(
        obj, "traffic_meter_egress");
    if (!prog_egress) {
        fprintf(stderr, "Failed to find egress program in BPF object\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_egress_fd = bpf_program__fd(prog_egress);
    if (bpf_prog_attach(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0) < 0) {
        perror("bpf_prog_attach(egress)");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /*
     * Find and attach the ingress (incoming traffic) BPF program.
     * BPF_CGROUP_INET_INGRESS hook is called for all incoming packets.
     */
    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(
        obj, "traffic_meter_ingress");
    if (!prog_ingress) {
        fprintf(stderr, "Failed to find ingress program in BPF object\n");
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }
    int prog_ingress_fd = bpf_program__fd(prog_ingress);
    if (bpf_prog_attach(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, 0) < 0) {
        perror("bpf_prog_attach(ingress)");
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    /*
     * Create ring buffer manager to receive events from the kernel.
     * The callback handle_event() is called for each event.
     */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_object__find_map_fd_by_name(obj, "events"),
        handle_event,  /* Callback function */
        NULL,          /* User context (unused) */
        NULL);         /* Options (use defaults) */
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

    /*
     * Main event loop - poll ring buffer for events.
     * Timeout of 100ms allows periodic checking of the exiting flag.
     */
    while (!exiting) {
        ring_buffer__poll(rb, 100);  /* 100ms timeout */
    }

    /*
     * Cleanup: detach BPF programs and free resources.
     * Programs are automatically unloaded when we close the object.
     */
    ring_buffer__free(rb);
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_object__close(obj);
    close(cgroup_fd);

    printf("Detached and exiting.\n");
    return 0;
}
