# eBPF Traffic Meter

A per-user network traffic monitoring tool using eBPF. Captures all IPv4 network traffic and logs it to per-user files with direction, bytes, and IP addresses.

**Note**:The current active branch is `ipv6-support` which includes both IPv6 support and IP-based packet filtering to ignore packets exchanged between
user specified endpoints.

## Requirements

- Linux kernel 5.8+ (for ring buffer support)
- clang (for BPF compilation)
- libbpf, libelf, libz development headers
- Root privileges (for loading eBPF programs)

### Fedora/RHEL

```bash
sudo dnf install clang libbpf-devel elfutils-libelf-devel zlib-devel
```

### Ubuntu/Debian

```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev
```

## Building

```bash
make clean && make
```

This produces:
- `traffic_meter.bpf.o` - eBPF program object
- `traffic_meter_user` - User-space loader

## Usage

```bash
sudo ./traffic_meter_user [cgroup_path] [nic_id]
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `cgroup_path` | `/sys/fs/cgroup/user.slice` | Cgroup to attach to (falls back to `/sys/fs/cgroup`) |
| `nic_id` | `unknown` | Identifier for log filenames |

### Examples

```bash
# Default cgroup, specify NIC for filename
sudo ./traffic_meter_user "" eno1

# Specific cgroup path
sudo ./traffic_meter_user /sys/fs/cgroup/user.slice/user-1000.slice eth0

# Monitor all traffic (root cgroup)
sudo ./traffic_meter_user /sys/fs/cgroup wlan0
```

Press `Ctrl+C` to stop.

## Output

Log files are written to `/tmp/traffic_user_<nic_id>_<uid>.log` in CSV format:

```
direction,bytes,src_ip,dst_ip,timestamp,total_in,total_out
```

### Fields

| Field | Description |
|-------|-------------|
| `direction` | `in` (received) or `out` (sent) |
| `bytes` | Packet size in bytes |
| `src_ip` | Source IPv4 address |
| `dst_ip` | Destination IPv4 address |
| `timestamp` | Unix timestamp with nanosecond precision (seconds.nanoseconds) |
| `total_in` | Cumulative bytes received so far for this UID |
| `total_out` | Cumulative bytes sent so far for this UID |

### Example Output

```csv
out,52,192.168.1.100,8.8.8.8,1732985432.123456789,0,52
in,84,8.8.8.8,192.168.1.100,1732985432.234567890,84,52
out,1500,192.168.1.100,142.250.185.78,1732985433.345678901,84,1552
in,1500,142.250.185.78,192.168.1.100,1732985433.456789012,1584,1552
```

## How It Works

1. **eBPF Program** (`traffic_meter.bpf.c`):
   - Attaches to `cgroup_skb/egress` and `cgroup_skb/ingress` hooks
   - Uses `bpf_get_socket_uid()` to identify the socket owner (UID)
   - Extracts source/destination IPs from IPv4 headers
   - Sends events to user space via ring buffer

2. **User-Space Loader** (`traffic_meter_user.c`):
   - Loads and attaches the eBPF programs to the specified cgroup
   - Polls the ring buffer for events
   - Passes events to pluggable output backend
   - Default backend writes CSV to per-user log files

## Architecture

The output system uses a pluggable backend interface:

```c
struct output_backend {
    int (*init)(void *config);
    int (*write)(const struct traffic_record *rec);
    void (*close)(void);
};
```

To add new output targets (syslog, network socket, database, etc.), implement this interface and set `g_backend` to your implementation.

## Limitations

- IPv4 only (IPv6 support available in `ipv6-support` branch)
- Monitors cgroup-based traffic (user processes), not raw interface traffic
- Requires cgroup v2

## License

GPL (required for eBPF programs using GPL-only helpers)
