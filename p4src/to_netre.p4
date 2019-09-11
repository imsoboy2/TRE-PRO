/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
*********************** CONSTANTS AND TYPES*******************************
*************************************************************************/
const int MAX_LEN = 10;
const int INGRESS = 1;
const int EGRESS = 0;
const int IPV4_PROTOCOL_TCP 6
const int IPV4_PROTOCOL_UDP 17

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_h {
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

header tcp_h {
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

header udp_h { 
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}


header tre_bitmap_h {
    bit<5> count; // fixed
    bit<10> bitmap;
    bit<1> reserved;
}

header chunk_h {
    bit<256> chunk_payload;
}
header token_h {
    bit<32> token_index; 
}
header_union u_chunk_token {
    chunk_t chunk;
    token_t token;
}

header finger_h {
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

struct metadata {
    parser_metadata_t parser_metadata;
    custom_metadata_t custom_metadata;

}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

parser IngressParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout ingress_intrinsic_metadata_t ig_intr_md) {
    
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        packet.extracting(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition set_metadata;
    }
    state set_metadata { //default tre 
        meta.parser_metadata.enable_tre = 1;
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
        packet.extract(hdr.tcp);        
        transition select(meta.parser_metadata.enable_tre) {
            1 : parse_tre_bitmap;
            0 : accept;
        }
    }
     state parse_udp {
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

    apply {
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

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
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

//레지스터에서 값 읽어오기 -> 레지스터.read(임시 저장, 인덱스)

    apply{
        selection(INGRESS);
        if(meta.custom_metadata.selection == 1){ //at ingress switch
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
                if(tmp_finger_value != 0) { //hash_collision //값이 있었을 때
                    
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
        if(meta.custom_metadata.selection == 0) { //at egress switch

        }
        */  


   
 
}
                 }


/*************************************************************************
*********************** E G R E S S D E P A R S E R  *********************
*************************************************************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;



//dddd
control DeadDrop(
    inout dead_drop_h dead_drop,
    inout PortId_t    dest,
    inout bit<3>      drop_ctl)
    (bit<32>          num_boxes)
{
    Register<data_t, box_num_t>(num_boxes) data_storage;
    
    RegisterAction<data_t, box_num_t, data_t>(data_storage)
    leave_data = {
        void apply(inout data_t register_data) {
            register_data = dead_drop.box_data;-+
             
        }
    };
    
    RegisterAction<data_t, box_num_t, data_t>(data_storage)
    pickup_data = {
        void apply(inout data_t register_data, out data_t result) {
            result = register_data;
            register_data = 0xc01df00d;
        }
    };
    
    Register<dest_t, box_num_t>(num_boxes) dest_storage;
    
    RegisterAction<dest_t, box_num_t, dest_t>(dest_storage)
    store_dest = {
        void apply(inout dest_t register_data) {
            register_data = dead_drop.data_dest;
        }
    };
    RegisterAction<dest_t, box_num_t, dest_t>(dest_storage)
    get_dest = {
        void apply(inout dest_t register_data, out dest_t result) {
            result = register_data;
            register_data = 511;
        }
    };
    
    apply {
        if (dead_drop.isValid()) {
            if (dead_drop.box_op == box_op_t.DROPOFF) {
                leave_data.execute(dead_drop.box_num);
                store_dest.execute(dead_drop.box_num);
                drop_ctl = 1;
                exit;
            } else {
                dead_drop.box_data = pickup_data.execute(dead_drop.box_num);
                dest = (PortId_t)get_dest.execute(dead_drop.box_num);
                drop_ctl = 0;
            exit;
            }
        }
    }
}
