#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define MAX_PKT_RATE 1000  // packets per second threshold

struct bpf_map_def SEC("maps") ip_counter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10240,
};

struct bpf_map_def SEC("maps") blocked_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 10240,
};

SEC("xdp")
int xdp_advanced_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Check if IP is already blocked
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked)
        return XDP_DROP;

    // Count packets per IP
    __u64 *count = bpf_map_lookup_elem(&ip_counter, &src_ip);
    __u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
        if (new_count > MAX_PKT_RATE) {
            __u8 flag = 1;
            bpf_map_update_elem(&blocked_ips, &src_ip, &flag, BPF_ANY);
            return XDP_DROP;
        }
    }
    bpf_map_update_elem(&ip_counter, &src_ip, &new_count, BPF_ANY);

    // Drop malformed TCP SYN packets
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_DROP;
        if (tcp->syn && !tcp->ack && tcp->doff < 5)
            return XDP_DROP;
    }

    // Drop UDP packets with tiny payloads
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_DROP;
        if (ntohs(udp->len) < 8)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
