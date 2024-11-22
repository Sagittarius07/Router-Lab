#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

std::vector<RoutingTableEntry> RoutingTable;

bool prefix_match(const in6_addr addr, const in6_addr prefix, uint32_t len) {
    for (int i = 0; i < len / 8; i++) {
        if (addr.s6_addr[i] != prefix.s6_addr[i]) {
            return false;
        }
    }
    if (len % 8) {
        uint8_t mask = 0xff << (8 - len % 8);
        if ((addr.s6_addr[len / 8] & mask) != (prefix.s6_addr[len / 8] & mask)) {
            return false;
        }
    }
    return true;
}


void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  if(insert){
    for(int i = 0; i < RoutingTable.size(); i++){
      if(RoutingTable[i].addr == entry.addr && RoutingTable[i].len == entry.len){
        RoutingTable[i] = entry;
        return;
      }
    }
    RoutingTable.push_back(entry);
  }
  else{
    for(int i = 0; i < RoutingTable.size(); i++){
      if(RoutingTable[i].addr == entry.addr && RoutingTable[i].len == entry.len){
        RoutingTable.erase(RoutingTable.begin() + i);
        return;
      }
    }
  }
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  if (!nexthop || !if_index) {
    return false;  // 避免空指针操作
  }

  int max_len = -1;
  for (int i = 0; i < RoutingTable.size(); i++) {
    if (prefix_match(addr, RoutingTable[i].addr, RoutingTable[i].len)) {
      if (RoutingTable[i].len > max_len) {
        max_len = RoutingTable[i].len;
        *nexthop = RoutingTable[i].nexthop;
        *if_index = RoutingTable[i].if_index;
      }
    }
  }
  return max_len != -1;
}



int mask_to_len(const in6_addr mask) {
    int len = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t byte = mask.s6_addr[i];
        if (byte == 0xff) {
            len += 8;
        } else if (byte == 0x00) {
            break;
        } else {
            for (int j = 7; j >= 0; j--) {
                if (byte & (1 << j)) {
                    len++;
                } else {
                    for (int k = j - 1; k >= 0; k--) {
                        if (byte & (1 << k)) {
                            return -1;
                        }
                    }
                    break;
                }
            }
            break;
        }
    }
    return len;
}

in6_addr len_to_mask(int len) {
  in6_addr mask = {};
  if (len < 0 || len > 128) {
    return mask;  
  }
  for (int i = 0; i < len / 8; i++) {
    mask.s6_addr[i] = 0xff;
  }
  if (len % 8) {
    mask.s6_addr[len / 8] = 0xff << (8 - len % 8);
  }
  return mask;
}

