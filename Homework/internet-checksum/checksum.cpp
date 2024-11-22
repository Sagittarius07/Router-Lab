#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint32_t cal_checksum(uint16_t *p, size_t len){
  uint32_t sum = 0;

  for(int i = 0; i < len / 2; i++){
    sum += *(p+i);
  }

  if(len % 2){
    sum += (*(uint8_t *)(p + len - 1) << 8);
  }

  return sum;
}

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) {
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // checksum: udp->uh_sum
    if (udp->uh_sum == 0x0000){
      return false;
    }
    size_t udp_len = ntohs(udp->uh_ulen);
    uint32_t udp_len_net = htonl(udp_len);

    uint8_t psuedo_header[40];
    memcpy(psuedo_header, &ip6->ip6_src, 16);
    memcpy(psuedo_header + 16, &ip6->ip6_dst, 16);
    memcpy(psuedo_header + 32, &udp_len_net, 4);
    memset(psuedo_header + 36, 0, 3);
    *(psuedo_header + 39) = nxt_header;

    uint32_t sum = 0;
    sum += cal_checksum((uint16_t *)psuedo_header, 40);
    sum += cal_checksum((uint16_t *)udp, udp_len);

    while(sum >> 16){
      sum = (sum & 0xFFFF) + (sum >> 16);
    }

    bool checksum = (sum == 0xFFFF);
    
    //

    udp->uh_sum = 0x0000;
    sum = 0;
    sum += cal_checksum((uint16_t *)psuedo_header, 40);
    sum += cal_checksum((uint16_t *)udp, udp_len);

    while(sum >> 16){
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    if(sum == 0xFFFF){
      sum = 0;
    }

    udp->uh_sum = htons(~sum);
    return checksum; 

  } else if (nxt_header == IPPROTO_ICMPV6) {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum

    size_t icmp6_len = len - sizeof(struct ip6_hdr);
    uint32_t icmp6_len_net = htonl(icmp6_len);

    uint8_t psuedo_header[40];
    memcpy(psuedo_header, &ip6->ip6_src, 16);
    memcpy(psuedo_header + 16, &ip6->ip6_dst, 16);
    memcpy(psuedo_header + 32, &icmp6_len_net, 4);
    memset(psuedo_header + 36, 0, 3);
    *(psuedo_header + 39) = nxt_header;

    uint32_t sum = 0;
    sum += cal_checksum((uint16_t *)psuedo_header, 40);
    sum += cal_checksum((uint16_t *)icmp, icmp6_len);

    while(sum >> 16){
      sum = (sum & 0xFFFF) + (sum >> 16);
    }

    bool checksum = (sum == 0xFFFF);

    icmp->icmp6_cksum = 0;

    sum = 0;
    sum +=cal_checksum((uint16_t *)psuedo_header, 40);
    sum +=cal_checksum((uint16_t *)icmp, icmp6_len);

    if(sum == 0){
      sum = 0xFFFF;
    }

    icmp->icmp6_cksum = htons(~sum);

    return checksum;

  } else {
    assert(false);
  }
  return true;
}
