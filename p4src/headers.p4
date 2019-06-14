
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define MAX_LEN 14 
// Mean packet size of standard ipv4 packet 420bytes? from caida

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t { 
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header chunk_t {
//Min chunk size ? : need 150bytes  
//chunk size 32bytes
    bit<256> payload;

}

header token_t {

    bit<1> bitmap1;
    bit<1> bitmap2;
    bit<1> bitmap3;
    bit<32> index;
}




struct parser_metadata_t {
    bit<4> remaining;

}

struct custom_metadata_t {
    bit<10> fingerprint[5];
    bit<256> left_value[5];
    bit<256> right_value[5];
}

struct metadata {
    
    parser_metadta_t parser_metadata;
    custom_metadata_t custom_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp; 
    chunk_t[MAX_LEN] chunk;
    token_t[MAX_LEN] token;
}

