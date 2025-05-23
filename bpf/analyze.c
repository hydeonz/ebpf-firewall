#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_debug(fmt, ...) \
    ({ char ____fmt[] = fmt; \
       bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

struct conn_stats {
    __u32 count;
    __u32 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct conn_stats));
    __uint(max_entries, 10000);
} connection_map SEC(".maps");

// Мапа для общего количества байт
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} total_bytes SEC(".maps");

// Мапа для подсчета TCP_SYN (ключ 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} tcp_syn_count SEC(".maps");

// Мапа для подсчета TCP_ACK (ключ 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} tcp_ack_count SEC(".maps");

SEC("xdp")
int analyze_connections(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 packet_length = data_end - data;

    // Обновляем общее количество байт
    __u32 key = 0;
    __u64 *total = bpf_map_lookup_elem(&total_bytes, &key);

    if (!total) {
        // Инициализируем если еще не существует
        __u64 init_val = 0;
        bpf_map_update_elem(&total_bytes, &key, &init_val, BPF_NOEXIST);
        total = bpf_map_lookup_elem(&total_bytes, &key);
        if (!total) {
            return XDP_PASS;
        }
    }

    // Атомарное обновление счетчика
    __sync_fetch_and_add(total, packet_length);

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void*)(ip + 1);
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    // Проверяем TCP флаги
    if (tcp->syn) {
        __u64 *syn_count = bpf_map_lookup_elem(&tcp_syn_count, &key);
        if (!syn_count) {
            __u64 init_val = 1;
            bpf_map_update_elem(&tcp_syn_count, &key, &init_val, BPF_NOEXIST);
        } else {
            __sync_fetch_and_add(syn_count, 1);
        }
    }

    if (tcp->ack) {
        __u64 *ack_count = bpf_map_lookup_elem(&tcp_ack_count, &key);
        if (!ack_count) {
            __u64 init_val = 1;
            bpf_map_update_elem(&tcp_ack_count, &key, &init_val, BPF_NOEXIST);
        } else {
            __sync_fetch_and_add(ack_count, 1);
        }
    }

    // работает в двух направлениях, можно сделать разбивку по входящему и исходящему трафику.
    __u32 src_ip = ip->saddr;
    struct conn_stats *stats = bpf_map_lookup_elem(&connection_map, &src_ip);
    struct conn_stats new_stats = {
        .count = 1,
        .bytes = packet_length
    };

    if (stats) {
        new_stats.count = stats->count + 1;
        new_stats.bytes = stats->bytes + packet_length;
    }

    bpf_map_update_elem(&connection_map, &src_ip, &new_stats, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";