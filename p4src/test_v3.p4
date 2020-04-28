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
    bit<5> count; // fixed
    bit<10> bitmap;
    bit<1> reserved;
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
    tcp_t      tcp;
    udp_t      udp; 
    tre_bitmap_t tre_bitmap;
    u_chunk_token[MAX_LEN] u_chunk_token;
    finger_t[MAX_LEN] finger;
    finger_t[MAX_LEN] finger_2;
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
}

/*
struct custom_metadata_t {
    bit<32>  fingerprint;
    bit<256> left_value;
    bit<256> right_value;
    bit<256> value;
}
*/
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
    
    state start { //default tre 
        meta.parser_metadata.enable_tre = TRUE;
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
        transition select(meta.parser_metadata.enable_tre) {
            1 : parse_tre_bitmap;
            0 : accept;
        }
    }
     state parse_udp {
        meta.parser_metadata.srcPort = hdr.udp.srcPort; 
        meta.parser_metadata.dstPort = hdr.udp.dstPort;
        packet.extract(hdr.udp);     
        transition select(meta.parser_metadata.enable_tre) {
            1 : parse_tre_bitmap;
            0 : accept;
        }
    }

   ///////////////////hdr.tre_bitmap.bitmap enter reversed order
   state parse_tre_bitmap {
        packet.extract(hdr.tre_bitmap);
        meta.custom_metadata.meta_bitmap = hdr.tre_bitmap.bitmap;
        //meta.custom_metadata.meta_count = hdr.tre_bitmap.count;
        meta.parser_metadata.remaining = MAX_LEN;
        transition select(hdr.tre_bitmap.bitmap) {
            0 : parse_all_chunk;
            default : parse_tre_select;
        }
    }
    ///(mainly) ingress, all chunk, no token
    state parse_all_chunk {
        packet.extract(hdr.u_chunk_token.next.chunk);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default : parse_all_chunk;
        }
    }
    
    ///egress router, chunks, tokens mix
    state parse_tre_select {
        meta.custom_metadata.meta_remainder = (bit<1>)(meta.custom_metadata.meta_bitmap % 2);
        meta.custom_metadata.meta_bitmap = meta.custom_metadata.meta_bitmap / 2;
        
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
        standard_metadata.egress_spec = 2;
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
    #define THRESHOLD 128
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
                clone3(CloneType.I2E, CONTROLLER_PORT, { standard_metadata });
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
    #define ENTRY_SIZE 524288
  
    bit<256> tmp_finger_value;
    bit<256> tmp_finger_value_2; 
    bit<64> tmp_count;
    bit<64> tmp_hash_collision_count; //hasch_collision
    bit<64> tmp_read_count;
    bit<64> tmp_store_count;
    
    register<bit<256>> (ENTRY_SIZE) fingerprint_store_2;
    register<bit<256>> (ENTRY_SIZE) fingerprint_store;
    register<bit<64>> (1) token_counter;
    register<bit<64>> (1) hash_collision_counter;
    //hasch_collision
    register<bit<64>> (1) read_counter;
    register<bit<64>> (1) store_counter;

    //register<bit<256>> (ENTRY_SIZE) left_store;
    //register<bit<256>> (ENTRY_SIZE) right_store;

    // In case of Ingress router
    action initial_setup(){
        meta.custom_metadata.meta_count = 0;
        meta.custom_metadata.meta_bitmap = 0;
        
        hdr.finger[0].setValid();
        hdr.finger[1].setValid();
        hdr.finger[2].setValid();
        hdr.finger[3].setValid();
        hdr.finger[4].setValid();
        hdr.finger[5].setValid();
        hdr.finger[6].setValid();
        hdr.finger[7].setValid();
        hdr.finger[8].setValid();
        hdr.finger[9].setValid();
        hdr.finger_2[0].setValid();
        hdr.finger_2[1].setValid();
        hdr.finger_2[2].setValid();
        hdr.finger_2[3].setValid();
        hdr.finger_2[4].setValid();
        hdr.finger_2[5].setValid();
        hdr.finger_2[6].setValid();
        hdr.finger_2[7].setValid();
        hdr.finger_2[8].setValid();
        hdr.finger_2[9].setValid();
    }

    action end_setup(){
        hdr.finger[0].setInvalid();
        hdr.finger[1].setInvalid();
        hdr.finger[2].setInvalid();
        hdr.finger[3].setInvalid();
        hdr.finger[4].setInvalid();
        hdr.finger[5].setInvalid();
        hdr.finger[6].setInvalid();
        hdr.finger[7].setInvalid();
        hdr.finger[8].setInvalid();
        hdr.finger[9].setInvalid();
        hdr.finger_2[0].setInvalid();
        hdr.finger_2[1].setInvalid();
        hdr.finger_2[2].setInvalid();
        hdr.finger_2[3].setInvalid();
        hdr.finger_2[4].setInvalid();
        hdr.finger_2[5].setInvalid();
        hdr.finger_2[6].setInvalid();
        hdr.finger_2[7].setInvalid();
        hdr.finger_2[8].setInvalid();
        hdr.finger_2[9].setInvalid();
   }

    action selection(bit<1> Z){
        meta.custom_metadata.selection = Z;
    }

    action fingerprinting_32() {
        hash(hdr.finger[0].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[0].chunk}, HASH_MAX); 
        hash(hdr.finger[1].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[1].chunk}, HASH_MAX); 
        hash(hdr.finger[2].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[2].chunk}, HASH_MAX); 
        hash(hdr.finger[3].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[3].chunk}, HASH_MAX); 
        hash(hdr.finger[4].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[4].chunk}, HASH_MAX); 
        hash(hdr.finger[5].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[5].chunk}, HASH_MAX); 
        hash(hdr.finger[6].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[6].chunk}, HASH_MAX); 
        hash(hdr.finger[7].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[7].chunk}, HASH_MAX); 
        hash(hdr.finger[8].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[8].chunk}, HASH_MAX); 
        hash(hdr.finger[9].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[9].chunk}, HASH_MAX); 
    }

    action fingerprinting_16() {
        hash(hdr.finger_2[0].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[0].chunk}, HASH_MAX);
        hash(hdr.finger_2[1].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[1].chunk}, HASH_MAX);
        hash(hdr.finger_2[2].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[2].chunk}, HASH_MAX);
        hash(hdr.finger_2[3].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[3].chunk}, HASH_MAX);
        hash(hdr.finger_2[4].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[4].chunk}, HASH_MAX);
        hash(hdr.finger_2[5].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[5].chunk}, HASH_MAX);
        hash(hdr.finger_2[6].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[6].chunk}, HASH_MAX);
        hash(hdr.finger_2[7].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[7].chunk}, HASH_MAX);
        hash(hdr.finger_2[8].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[8].chunk}, HASH_MAX);
        hash(hdr.finger_2[9].finger, HashAlgorithm.crc32, HASH_BASE, {hdr.u_chunk_token[9].chunk}, HASH_MAX);
    }

    action store_read(bit<4> X) {
        fingerprint_store.read(tmp_finger_value, hdr.finger[X].finger);
        tmp_read_count = tmp_read_count + 1;
    }

    action store_read_2(bit<4> X) {
        fingerprint_store_2.read(tmp_finger_value_2, hdr.finger_2[X].finger);
        tmp_read_count = tmp_read_count + 1;
    }
    
    action store_fingerprint(bit<4> Y) {
        fingerprint_store.write(hdr.finger[Y].finger, hdr.u_chunk_token[Y].chunk.chunk_payload);
        tmp_store_count = tmp_store_count + 1;
    }

    action store_fingerprint_2(bit<4> Y) {
        fingerprint_store_2.write(hdr.finger_2[Y].finger, hdr.u_chunk_token[Y].chunk.chunk_payload);
        tmp_store_count = tmp_store_count + 1;
    }

    
    action tokenization(bit<10> K) {
        token_counter.read(meta.custom_metadata.token_counter,0);
        meta.custom_metadata.token_counter = meta.custom_metadata.token_counter + 1;
        token_counter.write(0, meta.custom_metadata.token_counter);
        token_counter.read(tmp_count,0);
        meta.custom_metadata.meta_count = meta.custom_metadata.meta_count + 1;
        meta.custom_metadata.meta_bitmap =  meta.custom_metadata.meta_bitmap + 2^(9-K);
        hdr.u_chunk_token[K].chunk.setInvalid();
        hdr.u_chunk_token[K].token.setValid();
        hdr.u_chunk_token[K].token.token_index = hdr.finger[K].finger;
    }

    action tokenization_2(bit<10> K) {
        token_counter.read(meta.custom_metadata.token_counter,0);
        meta.custom_metadata.token_counter = meta.custom_metadata.token_counter + 1;
        token_counter.write(0, meta.custom_metadata.token_counter);
        token_counter.read(tmp_count,0);
        meta.custom_metadata.meta_count = meta.custom_metadata.meta_count + 1;
        meta.custom_metadata.meta_bitmap =  meta.custom_metadata.meta_bitmap + 2^(9-K);
        hdr.u_chunk_token[K].chunk.setInvalid();
        hdr.u_chunk_token[K].token.setValid();
        hdr.u_chunk_token[K].token.token_index = hdr.finger_2[K].finger;
    }

    action bitmap_gen(){
         hdr.tre_bitmap.setValid();
         hdr.tre_bitmap.count = meta.custom_metadata.meta_count;
         hdr.tre_bitmap.bitmap = meta.custom_metadata.meta_bitmap;   
         hdr.tre_bitmap.reserved = 0;
    }

    action tre_flag_off() {
        meta.parser_metadata.enable_tre = FALSE;
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
            tre_flag_off;
            NoAction();
        }
        size = 2048;
        default_action = tre_flag_off;
    }

//레지스터에서 값 읽어오기 -> 레지스터.read(임시 저장, 인덱스)

    apply {
        selection(INGRESS);
        
        is_hot_flow.apply();

        if(meta.parser_metadata.enable_tre == TRUE && meta.custom_metadata.selection == INGRESS) { //at ingress switch
            initial_setup();

            fingerprinting_32();
            fingerprinting_16();            
            hash_collision_counter.read(tmp_hash_collision_count, 0); //hasch_collision
            read_counter.read(tmp_read_count, 0);
            store_counter.read(tmp_store_count, 0);
       
            store_read(0);
            store_read_2(0);
            if(tmp_finger_value == hdr.u_chunk_token[0].chunk.chunk_payload){
                tokenization(0);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[0].chunk.chunk_payload){
                            tokenization_2(0);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(0);
                    }
                }
                else {
                    store_fingerprint(0);
                }
            }
            

            store_read(1);
            store_read_2(1);
            if(tmp_finger_value == hdr.u_chunk_token[1].chunk.chunk_payload){
                tokenization(1);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[1].chunk.chunk_payload){
                            tokenization_2(1);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(1);
                    }
                }
                else {
                    store_fingerprint(1);
                }
            }
           

            store_read(2);
            store_read_2(2);
            if(tmp_finger_value == hdr.u_chunk_token[2].chunk.chunk_payload){
                tokenization(2);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[2].chunk.chunk_payload){
                            tokenization_2(2);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(2);
                    }
                }    
                else {
                    store_fingerprint(2);
                }
            }
            

            store_read(3);
            store_read_2(3);
            if(tmp_finger_value == hdr.u_chunk_token[3].chunk.chunk_payload){
                tokenization(3);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[3].chunk.chunk_payload){
                            tokenization_2(3);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(3);
                    }
                }    
                else {
                    store_fingerprint(3);
                }
            }
            

            store_read(4);
            store_read_2(4);
            if(tmp_finger_value == hdr.u_chunk_token[4].chunk.chunk_payload){
                tokenization(4);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[4].chunk.chunk_payload){
                            tokenization_2(4);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }

                    }    
                    else {
                        store_fingerprint_2(4);
                    }
                }   
                else {
                    store_fingerprint(4);
                }
            }
            

            store_read(5);
            store_read_2(5);
            if(tmp_finger_value == hdr.u_chunk_token[5].chunk.chunk_payload){
                tokenization(5);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[5].chunk.chunk_payload){
                            tokenization_2(5);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }

                    }    
                    else {
                        store_fingerprint_2(5);
                    }
                }    
                else {
                    store_fingerprint(5);
                }
            }
            

            store_read(6);
            store_read_2(6);
            if(tmp_finger_value == hdr.u_chunk_token[6].chunk.chunk_payload){
                tokenization(6);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[6].chunk.chunk_payload){
                            tokenization_2(6);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(6);
                    }
                }    
                else {
                    store_fingerprint(6);
                }
            }
            

            store_read(7);
            store_read_2(7);
            if(tmp_finger_value == hdr.u_chunk_token[7].chunk.chunk_payload){
                tokenization(7);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[7].chunk.chunk_payload){
                            tokenization_2(7);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(7);
                    }
                }    
                else {
                    store_fingerprint(7);
                }
            }
            


            store_read(8);
            store_read_2(8);
            if(tmp_finger_value == hdr.u_chunk_token[8].chunk.chunk_payload){
                tokenization(8);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[8].chunk.chunk_payload){
                            tokenization_2(8);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(8);
                    }
                }    
                else {
                    store_fingerprint(8);
                }
            }
            


            store_read(9);
            store_read_2(9);
            if(tmp_finger_value == hdr.u_chunk_token[9].chunk.chunk_payload){
                tokenization(9);
            }            
            else{
                if(tmp_finger_value != 0) { //hasch_collision //값이 있었을 때
                    
                    if(tmp_finger_value_2 != 0){
                        if(tmp_finger_value_2 == hdr.u_chunk_token[9].chunk.chunk_payload){
                            tokenization_2(9);
                        }
                        else{
                            tmp_hash_collision_count = tmp_hash_collision_count + 1;
                        }
                    }    
                    else {
                        store_fingerprint_2(9);
                    }
                }    
                else {
                    store_fingerprint(9);
                }
            }
            

            
        
            hash_collision_counter.write(0, tmp_hash_collision_count); //hasch_collision
            read_counter.write(0, tmp_read_count);
            store_counter.write(0, tmp_store_count);

            bitmap_gen();
            end_setup();
               
            

        }
        /*
        selection(EGRESS)
        else if(meta.parser_metadata.enable_tre == TRUE && meta.custom_metadata.selection == EGRESS) { // at egress switch

        }
        */  
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
        packet.emit(hdr.tre_bitmap);
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
