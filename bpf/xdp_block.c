#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define MAX_BLOCKED_IPS 256
#define MAX_BLOCKED_PORTS 1024
#define MAX_ALLOWED_IPS 256
#define MAX_ALLOWED_PORTS 1024

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct rule_key {
    __le32 ip;
    __u8 proto;
    __u8 direction; // 0 = src, 1 = dst
    __u16 port;    // 0 означает любое значение порта
};

// Карта для блокирующих правил
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS * 10);
    __type(key, struct rule_key);
    __type(value, __u8);
} blocked_rules SEC(".maps");

// Карта для разрешающих правил (более высокий приоритет)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IPS * 10);
    __type(key, struct rule_key);
    __type(value, __u8);
} allowed_rules SEC(".maps");

SEC("xdp")
int xdp_filter_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Инициализируем порты нулями (будет означать "любой порт")
    __u16 src_port = 0;
    __u16 dst_port = 0;

    // Проверяем транспортный заголовок только для TCP/UDP
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        struct udphdr *udp = (void *)ip + sizeof(*ip);

        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            src_port = bpf_ntohs(ip->protocol == IPPROTO_TCP ? tcp->source : udp->source);
            dst_port = bpf_ntohs(ip->protocol == IPPROTO_TCP ? tcp->dest : udp->dest);
        }
    }

    // Преобразуем IP-адреса из сетевого порядка в host порядок
    __be32 saddr = ip->saddr;
    __be32 daddr = ip->daddr;

    // Создаем ключи для проверки правил
    struct rule_key src_key = {
        .ip = saddr,
        .proto = ip->protocol,
        .direction = 0,
        .port = 0
    };

    struct rule_key dst_key = {
        .ip = daddr,
        .proto = ip->protocol,
        .direction = 1,
        .port = 0
    };

    struct rule_key src_port_key = {
        .ip = saddr,
        .proto = ip->protocol,
        .direction = 0,
        .port = src_port
    };

    struct rule_key dst_port_key = {
        .ip = daddr,
        .proto = ip->protocol,
        .direction = 1,
        .port = dst_port
    };

    // Сначала проверяем разрешающие правила (более высокий приоритет)
    // Проверяем правила с конкретными портами
    if (bpf_map_lookup_elem(&allowed_rules, &src_port_key)) {
        bpf_printk("ALLOWED OUTGOING: Src %pI4:%d Proto %d", &saddr, src_port, ip->protocol);
        return XDP_PASS;
    }

    if (bpf_map_lookup_elem(&allowed_rules, &dst_port_key)) {
        bpf_printk("ALLOWED INCOMING: Dst %pI4:%d Proto %d", &daddr, dst_port, ip->protocol);
        return XDP_PASS;
    }

    // Затем проверяем общие разрешающие правила без учета портов
    if (bpf_map_lookup_elem(&allowed_rules, &src_key)) {
        bpf_printk("ALLOWED OUTGOING: Src %pI4 Proto %d", &saddr, ip->protocol);
        return XDP_PASS;
    }

    if (bpf_map_lookup_elem(&allowed_rules, &dst_key)) {
        bpf_printk("ALLOWED INCOMING: Dst %pI4 Proto %d", &daddr, ip->protocol);
        return XDP_PASS;
    }

    // Только если нет разрешающих правил, проверяем блокирующие
    // Проверяем правила с конкретными портами
    if (bpf_map_lookup_elem(&blocked_rules, &src_port_key)) {
        bpf_printk("BLOCKED OUTGOING: Src %pI4:%d Proto %d", &saddr, src_port, ip->protocol);
        return XDP_DROP;
    }

    if (bpf_map_lookup_elem(&blocked_rules, &dst_port_key)) {
        bpf_printk("BLOCKED INCOMING: Dst %pI4:%d Proto %d", &daddr, dst_port, ip->protocol);
        return XDP_DROP;
    }

    // Проверяем общие блокирующие правила без учета портов
    if (bpf_map_lookup_elem(&blocked_rules, &src_key)) {
        bpf_printk("BLOCKED OUTGOING: Src %pI4 Proto %d", &saddr, ip->protocol);
        return XDP_DROP;
    }

    if (bpf_map_lookup_elem(&blocked_rules, &dst_key)) {
        bpf_printk("BLOCKED INCOMING: Dst %pI4 Proto %d", &daddr, ip->protocol);
        return XDP_DROP;
    }

    // Если нет ни разрешающих, ни блокирующих правил - пропускаем пакет
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";