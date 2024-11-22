#include "protocol_ospf.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint32_t IPV6_HEADER_LEN = 40;
const uint32_t OSPF_HEADER_LEN = 16;
const uint32_t OSPF_LSU_HEADER_LEN = 4;
const uint32_t OSPF_LSA_HEADER_LEN = 20;
const uint32_t OSPFv3_PROTOCOL = 89;
const uint32_t OSPF_ROUTER_LSA = 1;
const uint32_t OSPF_ROUTER_LSA_ENTRY_LEN = 16;

OspfErrorCode parse_ip(const uint8_t *packet, uint32_t len,
                       const uint8_t **lsa_start, int *lsa_num) {
  // TODO
  if(len < IPV6_HEADER_LEN){
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  uint16_t payload_len = ntohs(*(uint16_t *)(packet + 4));
  if(len != payload_len + IPV6_HEADER_LEN){
    return OspfErrorCode::ERR_BAD_LENGTH;
  }

  if(packet[6] != OSPFv3_PROTOCOL){
    return OspfErrorCode::ERR_IPV6_NEXT_HEADER_NOT_OSPF;
  }

  if(len < IPV6_HEADER_LEN + OSPF_HEADER_LEN){
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  uint8_t *ospf_header = (uint8_t *)(packet + IPV6_HEADER_LEN);
  uint16_t ospf_len = ntohs(*(uint16_t *)(ospf_header + 2));
  if(len != IPV6_HEADER_LEN + ospf_len){
    return OspfErrorCode::ERR_BAD_LENGTH;
  }

  if(ospf_header[4] != OspfType::OSPF_LSU){
    return OspfErrorCode::ERR_OSPF_NOT_LSU;
  }

  if(len < IPV6_HEADER_LEN + OSPF_HEADER_LEN + OSPF_LSU_HEADER_LEN){
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  *lsa_start = packet + IPV6_HEADER_LEN + OSPF_HEADER_LEN + OSPF_LSU_HEADER_LEN;
  *lsa_num = (* (uint32_t *)(ospf_header + OSPF_HEADER_LEN));
  return OspfErrorCode::SUCCESS;
}

OspfErrorCode disassemble(const uint8_t *lsa, uint16_t buf_len, uint16_t *len,
                          RouterLsa *output) {
  // TODO
  if(buf_len < OSPF_LSA_HEADER_LEN){
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  uint16_t lsa_len = ntohs(*(uint16_t *)(lsa + 18));
  if(buf_len < lsa_len){
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }
  *len = lsa_len;

  ospf_lsa_header *header = (ospf_lsa_header *)lsa;
  uint16_t checksum = ospf_lsa_checksum(header, ntohs(header->length)); 
  if(ntohs(checksum) != 0){
    return OspfErrorCode::ERR_LSA_CHECKSUM;
  }
  if(ntohs(header->ls_age) > LSA_MAX_AGE){
    return OspfErrorCode::ERR_LS_AGE;
  }
  if(ntohs(header->ls_sequence_number) != RESERVED_LS_SEQ){
    return OspfErrorCode::ERR_LS_SEQ;
  }
  if(ntohs((header->ls_type & 0x1FFF)) != OSPF_ROUTER_LSA){
    return OspfErrorCode::ERR_LSA_NOT_ROUTER;
  }
  if((lsa_len - 4 - OSPF_HEADER_LEN - OSPF_LSA_HEADER_LEN) % OSPF_ROUTER_LSA_ENTRY_LEN != 0){
    return OspfErrorCode::ERR_ROUTER_LSA_INCOMPLETE_ENTRY;
  }

  output->ls_age = ntohs(header->ls_age);
  output->link_state_id = ntohl(header->link_state_id);
  output->advertising_router = ntohl(header->advertising_router);
  output->ls_sequence_number = ntohl(header->ls_sequence_number);
  output->flags = lsa[8];
  output->zero = lsa[9];
  output->options = ntohs(*(uint16_t *)(lsa + 10));
  
  uint8_t *entry = (uint8_t *)(lsa + OSPF_LSA_HEADER_LEN + OSPF_HEADER_LEN + 4);
  uint16_t entry_num = (lsa_len - 4 - OSPF_HEADER_LEN - OSPF_LSA_HEADER_LEN) / OSPF_ROUTER_LSA_ENTRY_LEN;
  for(uint16_t i = 0; i < entry_num; i++){
    if(entry[0] < 1 || entry[0] > 4){
      return OspfErrorCode::ERR_ROUTER_LSA_ENTRY_TYPE;
    }
    if(entry[1] != 0){
      return OspfErrorCode::ERR_BAD_ZERO;
    }
    
    output->entries[i].type = entry[0];
    output->entries[i].metric = ntohs(*(uint16_t *)(entry + 2));
    output->entries[i].interface_id = ntohl(*(uint32_t *)(entry + 4));
    output->entries[i].neighbor_interface_id = ntohl(*(uint32_t *)(entry + 8));
    output->entries[i].neighbor_router_id = ntohl(*(uint32_t *)(entry + 12));
    entry += OSPF_ROUTER_LSA_ENTRY_LEN;
  }

  return OspfErrorCode::SUCCESS;
}