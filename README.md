# eBPF Traffic Meter

A per-user network traffic monitoring tool using eBPF. Captures all IPv4 network traffic and logs it to per-user files with direction, bytes, and IP addresses.

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
direction,bytes,src_ip,dst_ip
```

### Fields

| Field | Description |
|-------|-------------|
| `direction` | `in` (received) or `out` (sent) |
| `bytes` | Packet size in bytes |
| `src_ip` | Source IPv4 address |
| `dst_ip` | Destination IPv4 address |

### Example Output

```csv
out,52,192.168.1.100,8.8.8.8
in,84,8.8.8.8,192.168.1.100
out,1500,192.168.1.100,142.250.185.78
in,1500,142.250.185.78,192.168.1.100
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
   - Writes each event to the appropriate per-user log file

## Limitations

- IPv4 only (IPv6 support available in `ipv6-support` branch)
- Monitors cgroup-based traffic (user processes), not raw interface traffic
- Requires cgroup v2

## License

GPL (required for eBPF programs using GPL-only helpers)
