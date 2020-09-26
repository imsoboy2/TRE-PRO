/* -*- P4_16 -*- */

/* 
NETRE INGRESS - SIMPLE_SWITCH (V1MODEL) TARGET VERSION
*/

#include <core.p4>
#include <v1model.p4>

/*************************************************************************
***************************** D E F I N E ********************************
*************************************************************************/

#define MAX_LEN 11 
#define TRUE 1
#define FALSE 0 
#define SHIM_TCP 77 //NETRE reserved IPv4 Protocol ID
#define SHIM_UDP 78 //NETRE reserved IPv4 Protocol ID
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define FLOW_REGISTER_SIZE 65536
#define FLOW_HASH_BASE_0 16w0
#define FLOW_HASH_MAX_0 16w16383
#define FLOW_HASH_BASE_1 16w16384
#define FLOW_HASH_MAX_1 16w32767
#define FLOW_HASH_BASE_2 16w32768
#define FLOW_HASH_MAX_2 16w49151
#define FLOW_HASH_BASE_3 16w49152
#define FLOW_HASH_MAX_3 16w65535
#define THRESHOLD 128
#define CONTROLLER_PORT 10
#define ENTRY_SIZE 65536

typedef bit<32> chunk1_size_t;
typedef bit<8> chunk2_size_t;

/*************************************************************************
******************* H E A D E R S & M E T A D A T A **********************
*************************************************************************/

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
    bit<4> count;
    bit<1> reserved;
}

header chunk_t {
    chunk1_size_t chunk_payload_1;
    chunk2_size_t chunk_payload_2;
    chunk1_size_t chunk_payload_3;
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
    tcp_t      tcp;
    udp_t      udp; 
    tre_shim_t tre_shim;
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
    bit<11> mb;
    bit<20> hash_base;
    bit<20> hash_max;
    bit<16> pair_src_ID;
    bit<16> pair_dst_ID;
    bit<32> value_diff1;
    bit<8> value_diff2;
}

struct metadata {
    parser_metadata_t parser_metadata;
    custom_metadata_t custom_metadata;

}

/*************************************************************************
**************************** P A R S E R  ********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start { //default tre 
        meta.parser_metadata.enable_tre = FALSE;
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
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_TCP : parse_tcp;
            IPV4_PROTOCOL_UDP : parse_udp;   
            default: accept;
        }
    }   
    state parse_tcp {
        meta.parser_metadata.srcPort = hdr.tcp.srcPort; 
        meta.parser_metadata.dstPort = hdr.tcp.dstPort;
        packet.extract(hdr.tcp);       
        transition parse_chunk_array;
    }
     state parse_udp {
        meta.parser_metadata.srcPort = hdr.udp.srcPort;
        meta.parser_metadata.dstPort = hdr.udp.dstPort;
        packet.extract(hdr.udp);
        transition parse_chunk_array;
    }
    // NETRE Ingress Node: parsing chunks in array 
    state parse_chunk_array {
        packet.extract(hdr.u_chunk_token.next.chunk);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        meta.custom_metadata.meta_count = MAX_LEN - meta.parser_metadata.remaining;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default : parse_chunk_array;
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
    apply { 
        //Empty in this program
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

/*
NETRE ingress pipeline is responsible for deciding packet's egress port and counting packet statistics
*/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }    
    action set_egress() {
        standard_metadata.egress_spec = 3;
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

    register<bit<10>>(FLOW_REGISTER_SIZE) hot_flow_counter;
    register<bit<1>>(FLOW_REGISTER_SIZE) bloom_filter;

    apply {
        /* ----------------------- find hot flow ----------------------- */
        bit<16> register_idx;
        bit<10> tmp = 0;
        bit<10> min_count = 0;

        // count-min sketch, per flow statistics
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
            // apply bloom filter, delete duplicated report
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
                // clone(CloneType.I2E, CONTROLLER_PORT);
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
 
    chunk1_size_t tmp_payload_value_1;
    chunk2_size_t tmp_payload_value_2;
 
    #define REGISTER(i)                                                                                                                                       \
    register<chunk1_size_t> (ENTRY_SIZE) payload_value_store_1_##i;                                                                                                   \
    register<chunk2_size_t> (ENTRY_SIZE) payload_value_store_2_##i;                                                                                                   \
    register<chunk1_size_t> (ENTRY_SIZE) payload_value_store_3_##i;                                                                                                    \
    register<chunk2_size_t> (ENTRY_SIZE) payload_value_store_4_##i;                                                                                                    \
    action indexing_action_##i() {                                                                                                                               \
        hdr.index[##i##].setValid();                                                                                                                         \
        hash(hdr.index[##i##].index, HashAlgorithm.crc16, meta.custom_metadata.hash_base, {hdr.u_chunk_token[##i##].chunk}, meta.custom_metadata.hash_max); \
        payload_value_store_1_##i##.read(tmp_payload_value_1, (bit<32>)hdr.index[##i##].index); \
        meta.custom_metadata.value_diff1 = hdr.u_chunk_token[##i##].chunk.chunk_payload_1 - tmp_payload_value_1; \
        payload_value_store_3_##i##.read(tmp_payload_value_2, (bit<32>)hdr.index[##i##].index); \
        meta.custom_metadata.value_diff2 = hdr.u_chunk_token[##i##].chunk.chunk_payload_3 - tmp_payload_value_2; \
    }      

    // Define REGISTER & ACTION per chunk[##i##]
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

   // In case of Ingress router
    action initial_setup(){
        meta.custom_metadata.meta_bitmap = 0;
        hdr.tre_shim.setValid();
        hdr.tre_shim.dstSwitchID = meta.custom_metadata.pair_dst_ID;
        hdr.tre_shim.srcSwitchID = meta.custom_metadata.pair_src_ID;        
    }

    action tokenization(bit<11> K) {
        meta.custom_metadata.mb = 1 << K;
        meta.custom_metadata.meta_bitmap = meta.custom_metadata.meta_bitmap + meta.custom_metadata.mb;
        hdr.u_chunk_token[K].chunk.setInvalid();
        hdr.u_chunk_token[K].token.setValid();
        hdr.u_chunk_token[K].token.token_index = hdr.index[K].index;
    }

    action bitmap_gen(){
         hdr.tre_shim.bitmap = meta.custom_metadata.meta_bitmap;   
         hdr.tre_shim.reserved = 0;
         hdr.tre_shim.count = meta.custom_metadata.meta_count;
    }

    action set_pair(bit<16> a, bit<16> b){
        meta.custom_metadata.pair_src_ID = a;
        meta.custom_metadata.pair_dst_ID = b;
    }

    table table_initiate_tre {
        key = {
        }
        actions = {
            set_pair;
            NoAction();
        }
        default_action = NoAction;
    }

    action tre_control(bit<20> b, bit<20> m) {
        meta.parser_metadata.enable_tre = TRUE;
        meta.custom_metadata.hash_base = b;
        meta.custom_metadata.hash_max = m;
    }

    table table_tre_control {
        key = {
            meta.custom_metadata.pair_src_ID: exact;
            meta.custom_metadata.pair_dst_ID: exact;
        }
        actions = {
            tre_control;
            NoAction();
        }
        default_action = NoAction;
    }

    apply {
        table_initiate_tre.apply();
        table_tre_control.apply();
               
        if (meta.parser_metadata.enable_tre == TRUE) { // at ingress switch
            initial_setup();            
            if (hdr.ipv4.protocol == IPV4_PROTOCOL_TCP) { hdr.ipv4.protocol = SHIM_TCP; }
            else if (hdr.ipv4.protocol == IPV4_PROTOCOL_UDP) { hdr.ipv4.protocol = SHIM_UDP; }            
           
            indexing_action_0();
            if (hdr.u_chunk_token[0].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(0);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_0.write((bit<32>)hdr.index[0].index, hdr.u_chunk_token[0].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_0.write((bit<32>)hdr.index[0].index, hdr.u_chunk_token[0].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_0.write((bit<32>)hdr.index[0].index, hdr.u_chunk_token[0].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_0.write((bit<32>)hdr.index[0].index, hdr.u_chunk_token[0].chunk.chunk_payload_4); // overwrite
                    hdr.index[0].setInvalid();
                }
            }
            
            indexing_action_1();
            if (hdr.u_chunk_token[1].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(1);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_1.write((bit<32>)hdr.index[1].index, hdr.u_chunk_token[1].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_1.write((bit<32>)hdr.index[1].index, hdr.u_chunk_token[1].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_1.write((bit<32>)hdr.index[1].index, hdr.u_chunk_token[1].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_1.write((bit<32>)hdr.index[1].index, hdr.u_chunk_token[1].chunk.chunk_payload_4); // overwrite
                    hdr.index[1].setInvalid();
                }
            }

            indexing_action_2();
            if (hdr.u_chunk_token[2].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(2);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_2.write((bit<32>)hdr.index[2].index, hdr.u_chunk_token[2].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_2.write((bit<32>)hdr.index[2].index, hdr.u_chunk_token[2].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_2.write((bit<32>)hdr.index[2].index, hdr.u_chunk_token[2].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_2.write((bit<32>)hdr.index[2].index, hdr.u_chunk_token[2].chunk.chunk_payload_4); // overwrite
                    hdr.index[2].setInvalid();
                }
            }

            indexing_action_3();
            if (hdr.u_chunk_token[3].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(3);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_3.write((bit<32>)hdr.index[3].index, hdr.u_chunk_token[3].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_3.write((bit<32>)hdr.index[3].index, hdr.u_chunk_token[3].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_3.write((bit<32>)hdr.index[3].index, hdr.u_chunk_token[3].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_3.write((bit<32>)hdr.index[3].index, hdr.u_chunk_token[3].chunk.chunk_payload_4); // overwrite
                    hdr.index[3].setInvalid();
                }
            }

            indexing_action_4();
            if (hdr.u_chunk_token[4].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(4);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_4.write((bit<32>)hdr.index[4].index, hdr.u_chunk_token[4].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_4.write((bit<32>)hdr.index[4].index, hdr.u_chunk_token[4].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_4.write((bit<32>)hdr.index[4].index, hdr.u_chunk_token[4].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_4.write((bit<32>)hdr.index[4].index, hdr.u_chunk_token[4].chunk.chunk_payload_4); // overwrite
                    hdr.index[4].setInvalid();
                }
            }

            indexing_action_5();
            if (hdr.u_chunk_token[5].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(5);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_5.write((bit<32>)hdr.index[5].index, hdr.u_chunk_token[5].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_5.write((bit<32>)hdr.index[5].index, hdr.u_chunk_token[5].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_5.write((bit<32>)hdr.index[5].index, hdr.u_chunk_token[5].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_5.write((bit<32>)hdr.index[5].index, hdr.u_chunk_token[5].chunk.chunk_payload_4); // overwrite
                    hdr.index[5].setInvalid();
                }
            }

            indexing_action_6();
            if (hdr.u_chunk_token[6].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(6);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_6.write((bit<32>)hdr.index[6].index, hdr.u_chunk_token[6].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_6.write((bit<32>)hdr.index[6].index, hdr.u_chunk_token[6].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_6.write((bit<32>)hdr.index[6].index, hdr.u_chunk_token[6].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_6.write((bit<32>)hdr.index[6].index, hdr.u_chunk_token[6].chunk.chunk_payload_4); // overwrite
                    hdr.index[6].setInvalid();
                }
            }

            indexing_action_7();
            if (hdr.u_chunk_token[7].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(7);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_7.write((bit<32>)hdr.index[7].index, hdr.u_chunk_token[7].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_7.write((bit<32>)hdr.index[7].index, hdr.u_chunk_token[7].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_7.write((bit<32>)hdr.index[7].index, hdr.u_chunk_token[7].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_7.write((bit<32>)hdr.index[7].index, hdr.u_chunk_token[7].chunk.chunk_payload_4); // overwrite
                    hdr.index[7].setInvalid();
                }
            }

            indexing_action_8();
            if (hdr.u_chunk_token[8].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(8);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_8.write((bit<32>)hdr.index[8].index, hdr.u_chunk_token[8].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_8.write((bit<32>)hdr.index[8].index, hdr.u_chunk_token[8].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_8.write((bit<32>)hdr.index[8].index, hdr.u_chunk_token[8].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_8.write((bit<32>)hdr.index[8].index, hdr.u_chunk_token[8].chunk.chunk_payload_4); // overwrite
                    hdr.index[8].setInvalid();
                }
            }

            indexing_action_9();
            if (hdr.u_chunk_token[9].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(9);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_9.write((bit<32>)hdr.index[9].index, hdr.u_chunk_token[9].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_9.write((bit<32>)hdr.index[9].index, hdr.u_chunk_token[9].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_9.write((bit<32>)hdr.index[9].index, hdr.u_chunk_token[9].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_9.write((bit<32>)hdr.index[9].index, hdr.u_chunk_token[9].chunk.chunk_payload_4); // overwrite
                    hdr.index[9].setInvalid();
                }
            }

            indexing_action_10();
            if (hdr.u_chunk_token[10].chunk.isValid()) {
                if(meta.custom_metadata.value_diff1 == 0 && meta.custom_metadata.value_diff2 == 0) { // cache hit
                    tokenization(10);
                } else { // register is empty or hash collision, overwrite the value
                    payload_value_store_1_10.write((bit<32>)hdr.index[10].index, hdr.u_chunk_token[10].chunk.chunk_payload_1); // overwrite
                    payload_value_store_2_10.write((bit<32>)hdr.index[10].index, hdr.u_chunk_token[10].chunk.chunk_payload_2); // overwrite
                    payload_value_store_3_10.write((bit<32>)hdr.index[10].index, hdr.u_chunk_token[10].chunk.chunk_payload_3); // overwrite
                    payload_value_store_4_10.write((bit<32>)hdr.index[10].index, hdr.u_chunk_token[10].chunk.chunk_payload_4); // overwrite
                    hdr.index[10].setInvalid();
                }
            }

            bitmap_gen();
        }
        
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
        packet.emit(hdr.tre_shim);
        packet.emit(hdr.u_chunk_token[0].chunk);
        packet.emit(hdr.u_chunk_token[0].token);
        packet.emit(hdr.u_chunk_token[1].chunk);
        packet.emit(hdr.u_chunk_token[1].token);
        packet.emit(hdr.u_chunk_token[2].chunk);
        packet.emit(hdr.u_chunk_token[2].token);
        packet.emit(hdr.u_chunk_token[3].chunk);
        packet.emit(hdr.u_chunk_token[3].token);
        packet.emit(hdr.u_chunk_token[4].chunk);
        packet.emit(hdr.u_chunk_token[4].token);
        packet.emit(hdr.u_chunk_token[5].chunk);
        packet.emit(hdr.u_chunk_token[5].token);
        packet.emit(hdr.u_chunk_token[6].chunk);
        packet.emit(hdr.u_chunk_token[6].token);
        packet.emit(hdr.u_chunk_token[7].chunk);
        packet.emit(hdr.u_chunk_token[7].token);
        packet.emit(hdr.u_chunk_token[8].chunk);
        packet.emit(hdr.u_chunk_token[8].token);
        packet.emit(hdr.u_chunk_token[9].chunk);
        packet.emit(hdr.u_chunk_token[9].token);
        packet.emit(hdr.u_chunk_token[10].chunk);
        packet.emit(hdr.u_chunk_token[10].token);

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