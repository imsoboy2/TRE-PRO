/* -*- P4_16 -*- */

/* 
NETRE EGRESS - SIMPLE_SWITCH (V1MODEL) TARGET VERSION
*/

#include <core.p4>
#include <v1model.p4>
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define MAX_LEN 11 
#define INGRESS 1
#define EGRESS  0
#define TRUE 1
#define FALSE 0 
#define null 0x0
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define SHIM_TCP 77
#define SHIM_UDP 78
#define ENTRY_SIZE 65536 //2^16

typedef bit<32> chunk1_size_t;
typedef bit<8> chunk2_size_t;

const bit<16> SWITCH_IP = 1;

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

header tre_shim_t {
    bit<11> bitmap;
    bit<16> srcSwitchID;
    bit<16> dstSwitchID;
    bit<4> bitmapcount;
    bit<1> reserved;
}

header chunk_t {
    chunk1_size_t chunk_payload_1;
    chunk1_size_t chunk_payload_2;
    chunk2_size_t chunk_payload_3;
    chunk2_size_t chunk_payload_4;
}

header token_t {
    bit<16> token_index; 
}

header_union u_chunk_token {
    chunk_t chunk;
    token_t token;
}

header index_t {
    bit<16> index;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tre_shim_t tre_shim;
    tcp_t      tcp;
    udp_t      udp; 
    u_chunk_token[MAX_LEN] u_chunk_token;
    index_t[MAX_LEN] index;
}

struct parser_metadata_t {
    bit<1> enable_tre;
    bit<4> remaining;
    bit<16> srcPort;
    bit<16> dstPort;
}

struct custom_metadata_t {
    bit<4> meta_count;
    bit<11> meta_bitmap;
    bit<1> meta_remainder;

    bit<16>  fingerprint;
    bit<256> value;

    bit<1> selection;
    bit<64> token_counter;
    bit<32> test_32;
    bit<256> test_256;

    bit<22> hash_base;
    bit<22> hash_max;
}

struct metadata {
    parser_metadata_t parser_metadata;
    custom_metadata_t custom_metadata;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start { 
        meta.parser_metadata.enable_tre = FALSE;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_TCP : parse_tcp;
            IPV4_PROTOCOL_UDP : parse_udp;
            SHIM_TCP: parse_tcp;
            SHIM_UDP: parse_udp;   
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.parser_metadata.srcPort = hdr.tcp.srcPort; 
        meta.parser_metadata.dstPort = hdr.tcp.dstPort;
        transition select(hdr.ipv4.protocol) {
            SHIM_TCP: parse_tre_shim;
            default: accept;
        }
    }

     state parse_udp {
        packet.extract(hdr.udp);
        meta.parser_metadata.srcPort = hdr.udp.srcPort;
        meta.parser_metadata.dstPort = hdr.udp.dstPort;
        transition select(hdr.ipv4.protocol) {
            SHIM_UDP: parse_tre_shim;
            default: accept;
        }
    }

   ///////////////////hdr.tre_shim.bitmap enter reversed order
   state parse_tre_shim {
        packet.extract(hdr.tre_shim);
        meta.custom_metadata.meta_bitmap = hdr.tre_shim.bitmap;
        meta.custom_metadata.meta_count = hdr.tre_shim.bitmapcount;
        transition select(hdr.tre_shim.dstSwitchID) {
            SWITCH_IP: parse_tre_select;
        }
    }
    
    ///egress router, chunks, tokens mix
    state parse_tre_select {
        meta.custom_metadata.meta_remainder = (bit<1>)(meta.custom_metadata.meta_bitmap % 2);
        meta.custom_metadata.meta_bitmap = meta.custom_metadata.meta_bitmap >> 1;        
        transition select(meta.custom_metadata.meta_remainder) {
            1 : parse_token;
            0 : parse_chunk;
        }
    }

    state parse_token {        
        packet.extract(hdr.u_chunk_token.next.token);        
        meta.custom_metadata.meta_count = meta.custom_metadata.meta_count -1;         
        transition select(meta.custom_metadata.meta_count) {
            0 : accept;
            default : parse_tre_select;
        }
    }

    state parse_chunk {
        packet.extract(hdr.u_chunk_token.next.chunk);      
        meta.custom_metadata.meta_count = meta.custom_metadata.meta_count -1;          
        transition select(meta.custom_metadata.meta_count) {
            0 : accept;
            default : parse_tre_select;
        }        
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
   update_checksum(
       hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action set_egress() {
        standard_metadata.egress_spec = 1;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_forwarding {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            NoAction();
            set_egress;
            drop;
        }
        size = 2048;
        default_action = set_egress;
    }
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (hdr.ipv4.protocol == SHIM_TCP) { hdr.ipv4.protocol = IPV4_PROTOCOL_TCP; }
            else if (hdr.ipv4.protocol == SHIM_UDP) { hdr.ipv4.protocol = IPV4_PROTOCOL_UDP; }
            ipv4_forwarding.apply();
            
        }
        else {
            NoAction();
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
        
    //IMPLEMENTATION: FIXED Chunking / Fingerprinting and FIXED MATCHING
  
    bit<32> tmp_index;
    
    #define REGISTER(i) \
        register<chunk1_size_t> (ENTRY_SIZE) payload_value_store_1_##i; \
        register<chunk1_size_t> (ENTRY_SIZE) payload_value_store_2_##i; \
        register<chunk2_size_t> (ENTRY_SIZE) payload_value_store_3_##i; \
        register<chunk2_size_t> (ENTRY_SIZE) payload_value_store_4_##i; \

    REGISTER(0)
    REGISTER(1)
    REGISTER(2)
    REGISTER(3)
    REGISTER(4)
    REGISTER(5)
    REGISTER(6)
    REGISTER(7)
    REGISTER(8)
    REGISTER(9)
    REGISTER(10)

    action end_setup() {
        hdr.tre_shim.setInvalid();
    }

    action tre_control(bit<22> b, bit<22> m) {
        meta.parser_metadata.enable_tre = TRUE;
        meta.custom_metadata.hash_base = b;
        meta.custom_metadata.hash_max = m;
    }

    table table_tre_control {
        key = {
            hdr.tre_shim.srcSwitchID: exact;
            hdr.tre_shim.dstSwitchID: exact;
        }
        actions = {
            tre_control;
            NoAction();
        }
        size = 2048;
        default_action = NoAction;
    }
    
    #define RESTORE_VALUE(i) \
        action restore_value##i##(bit<4> idx, bit<32> t) { \
            hdr.u_chunk_token[idx].chunk.setValid(); \
            payload_value_store_1_##i##.read(hdr.u_chunk_token[idx].chunk.chunk_payload_1, t); \
            payload_value_store_2_##i##.read(hdr.u_chunk_token[idx].chunk.chunk_payload_2, t); \
            payload_value_store_3_##i##.read(hdr.u_chunk_token[idx].chunk.chunk_payload_3, t); \
            payload_value_store_4_##i##.read(hdr.u_chunk_token[idx].chunk.chunk_payload_4, t); \
            hdr.u_chunk_token[idx].token.setInvalid(); \
        }

    RESTORE_VALUE(0)
    RESTORE_VALUE(1)
    RESTORE_VALUE(2)
    RESTORE_VALUE(3)
    RESTORE_VALUE(4)
    RESTORE_VALUE(5)
    RESTORE_VALUE(6)
    RESTORE_VALUE(7)
    RESTORE_VALUE(8)
    RESTORE_VALUE(9)
    RESTORE_VALUE(10)

    #define STORE_VALUE(i) \
        action store_payload_value##i##(bit<4> Y) { \
            hash(tmp_index, HashAlgorithm.crc16, meta.custom_metadata.hash_base, {hdr.u_chunk_token[Y].chunk}, meta.custom_metadata.hash_max); \
            payload_value_store_1_##i##.write(tmp_index, hdr.u_chunk_token[Y].chunk.chunk_payload_1); \
            payload_value_store_2_##i##.write(tmp_index, hdr.u_chunk_token[Y].chunk.chunk_payload_2); \
            payload_value_store_3_##i##.write(tmp_index, hdr.u_chunk_token[Y].chunk.chunk_payload_3); \
            payload_value_store_4_##i##.write(tmp_index, hdr.u_chunk_token[Y].chunk.chunk_payload_4); \
        }
    STORE_VALUE(0)
    STORE_VALUE(1)
    STORE_VALUE(2)
    STORE_VALUE(3)
    STORE_VALUE(4)
    STORE_VALUE(5)
    STORE_VALUE(6)
    STORE_VALUE(7)
    STORE_VALUE(8)
    STORE_VALUE(9)
    STORE_VALUE(10)

    apply {
        table_tre_control.apply();
               
        if(meta.parser_metadata.enable_tre == TRUE) { // at egress switch
            if (hdr.u_chunk_token[0].token.isValid() && hdr.tre_shim.bitmap[0:0] == 0x1) { // is token
                restore_value0(0, (bit<32>)hdr.u_chunk_token[0].token.token_index);
            } else if (hdr.u_chunk_token[0].chunk.isValid()){
                store_payload_value0(0);
            }

            if (hdr.u_chunk_token[1].token.isValid() && hdr.tre_shim.bitmap[1:1] == 0x1) { // is token
                restore_value1(1, (bit<32>)hdr.u_chunk_token[1].token.token_index);
            } else if (hdr.u_chunk_token[1].chunk.isValid()){
                store_payload_value1(1);
            }

            if (hdr.u_chunk_token[2].token.isValid() && hdr.tre_shim.bitmap[2:2] == 0x1) { // is token
                restore_value2(2, (bit<32>)hdr.u_chunk_token[2].token.token_index);
            } else if (hdr.u_chunk_token[2].chunk.isValid()){
                store_payload_value2(2);
            }

            if (hdr.u_chunk_token[3].token.isValid() && hdr.tre_shim.bitmap[3:3] == 0x1) { // is token
                restore_value3(3, (bit<32>)hdr.u_chunk_token[3].token.token_index);
            } else if (hdr.u_chunk_token[3].chunk.isValid()){
                store_payload_value3(3);
            }

            if (hdr.u_chunk_token[4].token.isValid() && hdr.tre_shim.bitmap[4:4] == 0x1) { // is token
                restore_value4(4, (bit<32>)hdr.u_chunk_token[4].token.token_index);
            } else if (hdr.u_chunk_token[4].chunk.isValid()){
                store_payload_value4(4);
            }

            if (hdr.u_chunk_token[5].token.isValid() && hdr.tre_shim.bitmap[5:5] == 0x1) { // is token
                restore_value5(5, (bit<32>)hdr.u_chunk_token[5].token.token_index);
            } else if (hdr.u_chunk_token[5].chunk.isValid()){
                store_payload_value5(5);
            }

            if (hdr.u_chunk_token[6].token.isValid() && hdr.tre_shim.bitmap[6:6] == 0x1) { // is token
                restore_value6(6, (bit<32>)hdr.u_chunk_token[6].token.token_index);
            } else if (hdr.u_chunk_token[6].chunk.isValid()){
                store_payload_value6(6);
            }

            if (hdr.u_chunk_token[7].token.isValid() && hdr.tre_shim.bitmap[7:7] == 0x1) { // is token
                restore_value7(7, (bit<32>)hdr.u_chunk_token[7].token.token_index);
            } else if (hdr.u_chunk_token[7].chunk.isValid()){
                store_payload_value7(7);
            }

            if (hdr.u_chunk_token[8].token.isValid() && hdr.tre_shim.bitmap[8:8] == 0x1) { // is token
                restore_value8(8, (bit<32>)hdr.u_chunk_token[8].token.token_index);
            } else if (hdr.u_chunk_token[8].chunk.isValid()){
                store_payload_value8(8);
            }

            if (hdr.u_chunk_token[9].token.isValid() && hdr.tre_shim.bitmap[9:9] == 0x1) { // is token
                restore_value9(9, (bit<32>)hdr.u_chunk_token[9].token.token_index);
            } else if (hdr.u_chunk_token[9].chunk.isValid()){
                store_payload_value9(9);
            }

            if (hdr.u_chunk_token[10].token.isValid() && hdr.tre_shim.bitmap[10:10] == 0x1) { // is token
                restore_value10(10, (bit<32>)hdr.u_chunk_token[10].token.token_index);
            } else if (hdr.u_chunk_token[10].chunk.isValid()){
                store_payload_value10(10);
            }
        }
        end_setup();
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.u_chunk_token[0].chunk);
        packet.emit(hdr.u_chunk_token[1].chunk);
        packet.emit(hdr.u_chunk_token[2].chunk);
        packet.emit(hdr.u_chunk_token[3].chunk);
        packet.emit(hdr.u_chunk_token[4].chunk);
        packet.emit(hdr.u_chunk_token[5].chunk);
        packet.emit(hdr.u_chunk_token[6].chunk);
        packet.emit(hdr.u_chunk_token[7].chunk);
        packet.emit(hdr.u_chunk_token[8].chunk);
        packet.emit(hdr.u_chunk_token[9].chunk);
        packet.emit(hdr.u_chunk_token[10].chunk);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;