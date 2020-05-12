/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define MAX_LEN 10 
#define INGRESS 1
#define EGRESS  0
#define TRUE 1
#define FALSE 0 
#define null 0x0


const bit<32> SWITCH_IP = 0x0A0A0001;

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

header tre_bitmap_t {
    bit<10> bitmap;
    bit<32> dstSwitchIp;
    bit<4> bitmapsize;
    bit<2> reserved;
}

header chunk_t {
    bit<256> chunk_payload;
}

header token_t {
    bit<32> token_index; 
}

header_union u_chunk_token {
    chunk_t chunk;
    token_t token;
}

header finger_t {
    bit<32> finger;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tre_bitmap_t tre_bitmap;
    tcp_t      tcp;
    udp_t      udp; 
    u_chunk_token[MAX_LEN] u_chunk_token;
    finger_t[MAX_LEN] finger;
}

struct parser_metadata_t {
    bit<1> enable_tre;
    bit<4> remaining;

    bit<16> srcPort;
    bit<16> dstPort;
}

struct custom_metadata_t {
    bit<5> meta_count;
    bit<10> meta_bitmap;
    bit<1> meta_remainder;

    bit<32>  fingerprint;
    bit<256> value;

    bit<1> selection;
    bit<64> token_counter;
    bit<32> test_32;
    bit<256> test_256;

    bit<19> hash_base;
    bit<19> hash_max;
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
        meta.parser_metadata.remaining = MAX_LEN;
        transition parse_ethernet;
        
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }

#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define SHIM_TCP 77
#define SHIM_UDP 78

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
            SHIM_TCP: parse_tre_bitmap;
            default: accept;
        }
    }
     state parse_udp {
        packet.extract(hdr.udp);
        meta.parser_metadata.srcPort = hdr.udp.srcPort;
        meta.parser_metadata.dstPort = hdr.udp.dstPort;
        transition select(hdr.ipv4.protocol) {
            SHIM_UDP: parse_tre_bitmap;
            default: accept;
        }
    }

   ///////////////////hdr.tre_bitmap.bitmap enter reversed order
   state parse_tre_bitmap {
        packet.extract(hdr.tre_bitmap);
        meta.custom_metadata.meta_bitmap = hdr.tre_bitmap.bitmap;

        meta.parser_metadata.enable_tre = TRUE;
        transition parse_tre_select;
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
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        packet.extract(hdr.u_chunk_token.next.token);         

        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default : parse_tre_select;
        }
    }

    state parse_chunk {
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        packet.extract(hdr.u_chunk_token.next.chunk);
        
        transition select(meta.parser_metadata.remaining) {
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

    #define FLOW_REGISTER_SIZE 65536
    #define FLOW_HASH_BASE_0 16w0
    #define FLOW_HASH_MAX_0 16w16383
    #define FLOW_HASH_BASE_1 16w16384
    #define FLOW_HASH_MAX_1 16w32767
    #define FLOW_HASH_BASE_2 16w32768
    #define FLOW_HASH_MAX_2 16w49151
    #define FLOW_HASH_BASE_3 16w49152
    #define FLOW_HASH_MAX_3 16w65535
    #define THRESHOLD 64
    #define CONTROLLER_PORT 10

    register<bit<10>>(FLOW_REGISTER_SIZE) hot_flow_counter;
    register<bit<1>>(FLOW_REGISTER_SIZE) bloom_filter;

    apply {

        /* ----------------------- find hot flow ----------------------- */
        bit<16> register_idx;
        bit<10> tmp = 0;
        bit<10> min_count = 0;

        // count per flow
        hash(register_idx, HashAlgorithm.crc32, FLOW_HASH_BASE_0, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.parser_metadata.srcPort, meta.parser_metadata.dstPort }, 
            FLOW_HASH_MAX_0);
        hot_flow_counter.read(tmp, (bit<32>)register_idx);
        hot_flow_counter.write((bit<32>)register_idx, tmp + 1);
        min_count = tmp + 1;

        hash(register_idx, HashAlgorithm.crc16, FLOW_HASH_BASE_1, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.parser_metadata.srcPort, meta.parser_metadata.dstPort }, 
            FLOW_HASH_MAX_1);
        hot_flow_counter.read(tmp, (bit<32>)register_idx);
        hot_flow_counter.write((bit<32>)register_idx, tmp + 1);
        if (min_count > tmp + 1) { min_count = tmp + 1; }

        hash(register_idx, HashAlgorithm.csum16, FLOW_HASH_BASE_2, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.parser_metadata.srcPort, meta.parser_metadata.dstPort }, 
            FLOW_HASH_MAX_2);
        hot_flow_counter.read(tmp, (bit<32>)register_idx);
        hot_flow_counter.write((bit<32>)register_idx, tmp + 1);
        if (min_count > tmp + 1) { min_count = tmp + 1; }

        hash(register_idx, HashAlgorithm.identity, FLOW_HASH_BASE_3, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.parser_metadata.srcPort, meta.parser_metadata.dstPort }, 
            FLOW_HASH_MAX_3);
        hot_flow_counter.read(tmp, (bit<32>)register_idx);
        hot_flow_counter.write((bit<32>)register_idx, tmp + 1);
        if (min_count > tmp + 1) { min_count = tmp + 1; }
        

        if (min_count >= THRESHOLD) {
            // apply bloom filter
            bit<1> bf0; bit<1> bf1; bit<1> bf2;
            bit<16> bf0_idx; bit<16> bf1_idx; bit<16> bf2_idx;
            hash(bf0_idx, HashAlgorithm.crc32, FLOW_HASH_BASE_0, 
                { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort },
                FLOW_HASH_MAX_3);
            bloom_filter.read(bf0, (bit<32>)bf0_idx);
            hash(bf1_idx, HashAlgorithm.crc16, FLOW_HASH_BASE_0, 
                { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort },
                FLOW_HASH_MAX_3);
            bloom_filter.read(bf1, (bit<32>)bf1_idx);
            hash(bf2_idx, HashAlgorithm.csum16, FLOW_HASH_BASE_0, 
                { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort },
                FLOW_HASH_MAX_3);
            bloom_filter.read(bf2, (bit<32>)bf2_idx);

            if (bf0 == 0 || bf2 == 0 || bf2 == 0) {
                // report flow to controller
                clone(CloneType.I2E, CONTROLLER_PORT);
                // -------------------------
                bloom_filter.write((bit<32>)bf0_idx, 1);
                bloom_filter.write((bit<32>)bf1_idx, 1);
                bloom_filter.write((bit<32>)bf2_idx, 1);
            }
        }
        
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
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

    //#define HASH_BASE 16w0
    //#define HASH_MAX  16w65535

    //#define HASH_BASE 16w0
    //#define HASH_MAX  16w65535

    #define HASH_BASE 19w0
    #define HASH_MAX  19w524287

    // #define HASH_BASE 20w0
    // #define HASH_MAX  20w1048575
    #define ENTRY_SIZE 4194304
  
    bit<256> tmp_finger_value;
    bit<64> tmp_count;
    bit<64> tmp_hash_collision_count; //hash_collision
    bit<64> tmp_read_count;
    bit<64> tmp_store_count;
    bit<32> tmp_finger;
    
    register<bit<256>> (ENTRY_SIZE) fingerprint_store;

    //register<bit<256>> (ENTRY_SIZE) left_store;
    //register<bit<256>> (ENTRY_SIZE) right_store;

    action end_setup() {
        hdr.tre_bitmap.setInvalid();
    }

    action tre_flag_on(bit<19> b, bit<19> m, bit<32> dstSwitchIp) {
        meta.parser_metadata.enable_tre = TRUE;
        meta.custom_metadata.hash_base = b;
        meta.custom_metadata.hash_max = m;
        hdr.tre_bitmap.dstSwitchIp = dstSwitchIp;
    }

    table is_hot_flow {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.protocol: exact;
            meta.parser_metadata.srcPort: exact;
            meta.parser_metadata.dstPort: exact;
        }
        actions = {
            tre_flag_on;
            NoAction();
        }
        size = 2048;
        default_action = NoAction;
    }

    //레지스터에서 값 읽어오기 -> 레지스터.read(임시 저장, 인덱스)
    action restore_token(bit<4> idx, bit<32> t) {
        hdr.u_chunk_token[idx].chunk.setValid();
        fingerprint_store.read(hdr.u_chunk_token[idx].chunk.chunk_payload, t);
        hdr.u_chunk_token[idx].token.setInvalid();
    }

    action store_fingerprint(bit<4> Y) {
        hash(tmp_finger, HashAlgorithm.crc32, meta.custom_metadata.hash_base, {hdr.u_chunk_token[Y].chunk}, meta.custom_metadata.hash_max); 
        fingerprint_store.write(tmp_finger, hdr.u_chunk_token[Y].chunk.chunk_payload);
    }

    apply {
        meta.parser_metadata.enable_tre = FALSE;
        is_hot_flow.apply();
        // meta.parser_metadata.enable_tre = TRUE;
        // meta.custom_metadata.hash_base = 0;
        // meta.custom_metadata.hash_max = 524287;
        
        if(meta.parser_metadata.enable_tre == TRUE) { // at egress switch
            if (hdr.tre_bitmap.bitmap[0:0] == 0x1) { // is token
                restore_token(0, hdr.u_chunk_token[0].token.token_index);
            } else if (hdr.u_chunk_token[0].chunk.isValid()){
                store_fingerprint(0);
            }

            if (hdr.tre_bitmap.bitmap[1:1] == 0x1) { // is token
                restore_token(1, hdr.u_chunk_token[1].token.token_index);
            } else if (hdr.u_chunk_token[1].chunk.isValid()){
                store_fingerprint(1);
            }

            if (hdr.tre_bitmap.bitmap[2:2] == 0x1) { // is token
                restore_token(2, hdr.u_chunk_token[2].token.token_index);
            } else if (hdr.u_chunk_token[2].chunk.isValid()){
                store_fingerprint(2);
            }

            if (hdr.tre_bitmap.bitmap[3:3] == 0x1) { // is token
                restore_token(3, hdr.u_chunk_token[3].token.token_index);
            } else if (hdr.u_chunk_token[3].chunk.isValid()){
                store_fingerprint(3);
            }

            if (hdr.tre_bitmap.bitmap[4:4] == 0x1) { // is token
                restore_token(4, hdr.u_chunk_token[4].token.token_index);
            } else if (hdr.u_chunk_token[4].chunk.isValid()){
                store_fingerprint(4);
            }

            if (hdr.tre_bitmap.bitmap[5:5] == 0x1) { // is token
                restore_token(5, hdr.u_chunk_token[5].token.token_index);
            } else if (hdr.u_chunk_token[5].chunk.isValid()){
                store_fingerprint(5);
            }

            if (hdr.tre_bitmap.bitmap[6:6] == 0x1) { // is token
                restore_token(6, hdr.u_chunk_token[6].token.token_index);
            } else if (hdr.u_chunk_token[6].chunk.isValid()){
                store_fingerprint(6);
            }

            if (hdr.tre_bitmap.bitmap[7:7] == 0x1) { // is token
                restore_token(7, hdr.u_chunk_token[7].token.token_index);
            } else if (hdr.u_chunk_token[7].chunk.isValid()){
                store_fingerprint(7);
            }

            if (hdr.tre_bitmap.bitmap[8:8] == 0x1) { // is token
                restore_token(8, hdr.u_chunk_token[8].token.token_index);
            } else if (hdr.u_chunk_token[8].chunk.isValid()){
                store_fingerprint(8);
            }

            if (hdr.tre_bitmap.bitmap[9:9] == 0x1) { // is token
                restore_token(9, hdr.u_chunk_token[9].token.token_index);
            } else if (hdr.u_chunk_token[9].chunk.isValid()){
                store_fingerprint(9);
            }

            if (hdr.ipv4.protocol == SHIM_TCP) { hdr.ipv4.protocol = IPV4_PROTOCOL_TCP; }
            else if (hdr.ipv4.protocol == SHIM_UDP) { hdr.ipv4.protocol = IPV4_PROTOCOL_UDP; }
        }
        hdr.tre_bitmap.setInvalid();
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