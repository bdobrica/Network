#include "libnetfilter_queue_headers.h"
#include "libnetfilter_queue.h"
#include <arpa/inet.h>

struct nfq_iphdr
{
    /*
#if defined(__LITTLE_ENDIAN_BITFIELD)
uint8_t  ihl:4,
version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
*/
    uint8_t   version:4,
              ihl:4;
    /*
#endif
*/
    uint8_t  tos;
    uint16_t  tot_len;
    uint16_t  id;
    uint16_t  frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t  saddr;
    uint32_t  daddr;
};

struct nfq_tcphdr
{
    uint16_t  source;
    uint16_t  dest;
    uint32_t  seq;
    uint32_t  ack_seq;
    /*
#if defined(__LITTLE_ENDIAN_BITFIELD)
uint16_t res1:4,
doff:4,
fin:1,
syn:1,
rst:1,
psh:1,
ack:1,
urg:1,
ece:1,
cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
*/
    uint16_t doff:4,
              res1:4,
              cwr:1,
              ece:1,
              urg:1,
              ack:1,
              psh:1,
              rst:1,
              syn:1,
              fin:1;
    /*
#endif
*/
    uint16_t  window;
    uint16_t check;
    uint16_t  urg_ptr;
};

struct nfq_udphdr
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

extern struct nfq_iphdr* nfq_get_iphdr(struct nfq_data *nfad)
{
    char *data;

    if(nfq_get_payload(nfad,&data)==-1)
        return NULL;
    return (struct nfq_iphdr*) data;
}

extern uint8_t nfq_get_ip_ihl(struct nfq_iphdr *hdr)
{
    return hdr->ihl;
}

extern uint8_t nfq_get_ip_version(struct nfq_iphdr *hdr)
{
    return hdr->version;
}

extern uint8_t nfq_get_ip_tos(struct nfq_iphdr *hdr)
{
    return hdr->tos;
}

extern uint16_t nfq_get_ip_tot_len(struct nfq_iphdr *hdr)
{
    return ntohs(hdr->tot_len);
}

extern uint16_t nfq_get_ip_id(struct nfq_iphdr *hdr)
{
    return ntohs(hdr->id);
}

extern uint16_t nfq_get_ip_fragoff(struct nfq_iphdr *hdr)
{
    return ntohs(hdr->frag_off);
}

extern uint8_t nfq_get_ip_ttl(struct nfq_iphdr *hdr)
{
    return hdr->ttl;
}

extern uint8_t nfq_get_ip_protocol(struct nfq_iphdr *hdr)
{
    return hdr->protocol;
}

extern uint16_t nfq_get_ip_check(struct nfq_iphdr *hdr)
{
    return ntohs(hdr->check);
}

extern uint32_t nfq_get_ip_saddr(struct nfq_iphdr *hdr)
{
    return ntohl(hdr->saddr);
}

extern uint32_t nfq_get_ip_daddr(struct nfq_iphdr *hdr)
{
    return ntohl(hdr->daddr);
}

extern struct nfq_tcphdr* nfq_get_tcphdr(struct nfq_data *nfad)
{
    char *data;

    if(nfq_get_payload(nfad,&data)==-1)
        return NULL;
    data=data+sizeof(struct nfq_iphdr);
    return (struct nfq_tcphdr*) data;
}

extern uint16_t nfq_get_tcp_source(struct nfq_tcphdr *hdr)
{
    return ntohs(hdr->source);
}

extern uint16_t nfq_get_tcp_dest(struct nfq_tcphdr *hdr)
{
    return ntohs(hdr->dest);
}

extern uint32_t nfq_get_tcp_seq(struct nfq_tcphdr *hdr)
{
    return ntohl(hdr->seq);
}

extern uint32_t nfq_get_tcp_ack_seq(struct nfq_tcphdr *hdr)
{
    return ntohl(hdr->ack_seq);
}

extern uint16_t nfq_get_tcp_flags(struct nfq_tcphdr *hdr)
{
    return ntohs(hdr->source);
}

/*
   extern uint16_t nfq_get_tcp_doff(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->source);
   }

   extern uint16_t nfq_get_tcp_res1(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->source);
   }

   extern uint16_t nfq_get_tcp_cwr(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->cwr);
   }

   extern uint16_t nfq_get_tcp_ece(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->ece);
   }

   extern uint16_t nfq_get_tcp_urg(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->urg);
   }

   extern uint16_t nfq_get_tcp_ack(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->ack);
   }

   extern uint16_t nfq_get_tcp_psh(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->psh);
   }

   extern uint16_t nfq_get_tcp_rst(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->rst);
   }

   extern uint16_t nfq_get_tcp_syn(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->syn);
   }

   extern uint16_t nfq_get_tcp_fin(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->fin);
   }

   extern uint16_t nfq_get_tcp_seq(struct nfq_tcphdr *hdr)
   {
   return ntohs(hdr->seq);
   }

*/
extern uint16_t nfq_get_tcp_window(struct nfq_tcphdr *hdr)
{
    return ntohs(hdr->window);
}

extern uint16_t nfq_get_tcp_check(struct nfq_tcphdr *hdr)
{
    return ntohs(hdr->check);
}

extern uint16_t nfq_get_tcp_urg_ptr(struct nfq_tcphdr *hdr)
{
    return ntohs(hdr->urg_ptr);
}

extern struct nfq_udphdr* nfq_get_udphdr(struct nfq_data *nfad)
{
    char *data;

    if(nfq_get_payload(nfad,&data)==-1)
        return NULL;

    data=data+sizeof(struct nfq_iphdr);
    return (struct nfq_udphdr*) data;
}

extern uint16_t nfq_get_udp_source(struct nfq_udphdr *hdr)
{
    return ntohs(hdr->source);
}

extern uint16_t nfq_get_udp_dest(struct nfq_udphdr *hdr)
{
    return ntohs(hdr->dest);
}

extern uint16_t nfq_get_udp_len(struct nfq_udphdr *hdr)
{
    return ntohs(hdr->len);
}

extern uint16_t nfq_get_udp_check(struct nfq_udphdr *hdr)
{
    return ntohs(hdr->check);
}
