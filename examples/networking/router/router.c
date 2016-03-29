#include "/home/ops/bcc/src/cc/export/proto.h"
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/pkt_cls.h>

/*
struct __sk_buff is passed by the kernel to this function
*/
int parse_pkt (struct __sk_buff * skb) {
    // Packet is available on the 0th location of the memory.
    u8 *cursor = 0;
    
    struct ethernet_t * ethernet = cursor_advance(cursor,
            sizeof(*ethernet));
    
    // If packet type is ARP
    if (ethernet->type == ETH_P_ARP)
        ;

    struct ip_t * ip = (struct ip_t *) cursor;
    u32 len = ip->hlen << 2;
    cursor_advance(cursor, len);
    
    // If next protocol is not ICMP, return
    if (ip->nextp != IPPROTO_ICMP)
            return 0;
    
    struct icmp_t * icmp = cursor_advance(cursor, sizeof(*icmp));
    // If ICMP packet is not echo, return
    if (icmp->type != ICMP_ECHO)
            return 0;
    
    /*
    Converting ICMP echo into ICMP reply by changing the type to 0
    Since we're changing packet contents, we need to update the checksum
    */
    unsigned short type = ICMP_ECHOREPLY;
    //incr_cksum_l4(&icmp->cksum, icmp->type, type, 1);
    bpf_l4_csum_replace(skb,36,icmp->type, type,sizeof(type));
    icmp->type = type;
    
    /*
    Swapping Source and Destination in IP header
    We don't need to update checksum since we're just swapping.
    However to demonstrate the use of incr_cksum_l3, the checksum
    is recomputed after each change
    */
    u32 old_src = ip->src;
    u32 old_dst = ip->dst;
    
    incr_cksum_l3(&ip->hchecksum, old_src, old_dst);
    ip->src = old_dst;
    incr_cksum_l3(&ip->hchecksum, old_dst, old_src);
    ip->dst = old_src;
    
    /* Swapping Mac Addresses
    Using two temp variables since assigning one memory location
    to another directly causes a compilation error.
    */
    u64 old_src_mac = ethernet->src;
    u64 old_dst_mac = ethernet->dst;
    
    ethernet->src = old_dst_mac;
    ethernet->dst = old_src_mac;
    
    u64 ret = bpf_redirect(skb->ifindex, 0 /*For Egress */);
    /*
    This output to the kernel trace_pipe which can also be read by:
    cat /sys/kernel/debug/tracing/trace_pipe
    */
    bpf_trace_printk("ICMP_SEQ: %u\\n", icmp->seq);
    return TC_ACT_REDIRECT;
}
