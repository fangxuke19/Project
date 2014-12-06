#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct iphdr {
         uint8_t    ihl:4,
                    version:4;
         uint8_t    tos;
         uint16_t   tot_len;
         uint16_t   id;
         uint16_t   frag_off;
         uint8_t    ttl;
         uint8_t    protocol;
         uint16_t   check;
         uint32_t   saddr;
         uint32_t   daddr;
 };
 struct tcphdr {
         uint16_t   source;
         uint16_t   dest;
         uint32_t   seq;
         uint32_t   ack_seq;
        uint8_t flags;
         uint16_t   window;
         uint16_t   check;
         uint16_t   urg_ptr;
 };
 struct udphdr {
        uint16_t   source;
        uint16_t   dest;
        uint16_t   len;
        uint16_t   check;
 };
  /*
  *struct for the ethernet header
  */
typedef struct {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint8_t ethertype[2];
  uint8_t data[0];
} ethernet_hdr_t;

#define IPV4 0X0800

