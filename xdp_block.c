#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

// Карта для хранения индекса блокируемого интерфейса
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_iface_map SEC(".maps");

SEC("xdp")
int xdp_dilih(struct xdp_md *ctx)
{
    // Получаем индекс интерфейса из карты
    __u32 key = 0;
    __u32 *iface_idx = bpf_map_lookup_elem(&blocked_iface_map, &key);
    
    // Если интерфейс совпадает с целевым - блокируем
    if (iface_idx && ctx->ingress_ifindex == *iface_idx) {
        bpf_printk("Blocking traffic on interface %d", *iface_idx);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
