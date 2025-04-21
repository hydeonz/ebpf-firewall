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
#define IPPROTO_ICMP 1

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

// Карта для глобальной блокировки
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
} global_block SEC(".maps");

// Карта для глобального разрешения (наивысший приоритет)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
} global_allow SEC(".maps");

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

    // Проверяем глобальное разрешение (наивысший приоритет)
    __u8 key = 0;
    __u8 *global_allow_enabled = bpf_map_lookup_elem(&global_allow, &key);
    if (global_allow_enabled && *global_allow_enabled) {
        return XDP_PASS;
    }

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

    // Сначала проверяем разрешающие правила (высокий приоритет)
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

    // Проверяем глобальную блокировку (если включена, блокируем весь трафик)
    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        return XDP_DROP;
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

SEC("classifier/egress")
int tc_egress_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Проверяем глобальное разрешение (наивысший приоритет)
    __u8 key = 0;
    __u8 *global_allow_enabled = bpf_map_lookup_elem(&global_allow, &key);
    if (global_allow_enabled && *global_allow_enabled) {
        return TC_ACT_OK;
    }

    // Проверяем, что пакет содержит Ethernet + IP заголовки
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK; // Пропускаем, если заголовок неполный

    // Фильтруем только IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // Получаем dst IP (для egress это адрес назначения)
    __be32 daddr = ip->daddr;

    // Проверяем порт (если TCP/UDP)
    __u16 dst_port = 0;
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        struct udphdr *udp = (void *)ip + sizeof(*ip);

        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            dst_port = bpf_ntohs(ip->protocol == IPPROTO_TCP ? tcp->dest : udp->dest);
        }
    }

    // Создаем ключ для проверки правил (direction = 1, так как это egress)
    struct rule_key dst_key = {
        .ip = daddr,
        .proto = ip->protocol,
        .direction = 1,
        .port = 0
    };

    struct rule_key dst_port_key = {
        .ip = daddr,
        .proto = ip->protocol,
        .direction = 1,
        .port = dst_port
    };

    // Сначала проверяем разрешающие правила (высокий приоритет)
    if (bpf_map_lookup_elem(&allowed_rules, &dst_port_key)) {
        bpf_printk("ALLOWED EGRESS (TC): Dst %pI4:%d Proto %d", &daddr, dst_port, ip->protocol);
        return TC_ACT_OK;
    }

    if (bpf_map_lookup_elem(&allowed_rules, &dst_key)) {
        bpf_printk("ALLOWED EGRESS (TC): Dst %pI4 Proto %d", &daddr, ip->protocol);
        return TC_ACT_OK;
    }

    // Проверяем глобальную блокировку
    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        return TC_ACT_SHOT; // Блокируем весь трафик
    }

    // Проверяем блокирующие правила
    if (bpf_map_lookup_elem(&blocked_rules, &dst_port_key)) {
        bpf_printk("BLOCKED EGRESS (TC): Dst %pI4:%d Proto %d", &daddr, dst_port, ip->protocol);
        return TC_ACT_SHOT;
    }

    if (bpf_map_lookup_elem(&blocked_rules, &dst_key)) {
        bpf_printk("BLOCKED EGRESS (TC): Dst %pI4 Proto %d", &daddr, ip->protocol);
        return TC_ACT_SHOT;
    }

    // Если правил нет - пропускаем пакет
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";