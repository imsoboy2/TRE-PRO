#include <core.p4>
#include <v1model.p4>
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define MAX_LEN 3 
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
    bit<1> enable_tre;
    bit<4> remaining;

}

struct custom_metadata_t {
    bit<32> fingerprint;
    bit<256> left_value;
    bit<256> right_value;
    bit<256> value;
}

struct metadata {
    
    parser_metadata_t parser_metadata;
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



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
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
        packet.extract(hdr.tcp);
        
        transition select(meta.parser_metadata.enable_tre) {
               1 : parse_payload;
               0 : accept;
        }
    }


     state parse_udp {
        packet.extract(hdr.udp);
        
        transition select(meta.parser_metadata.enable_tre) {
               1 : parse_payload;
               0 : accept;
        }
    }

    state parse_payload {
        packet.extract(hdr.chunk.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        transition select(meta.parser_metadata.remaining) {
               0 : accept;
               default : parse_payload;
        }
    }

}

/* -*- P4_16 -*- */

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
        mark_to_drop();
    }

    
    action set_egress(bit<9> port) {
        standard_metadata.egress_spec = port;
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
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0){

        ipv4_forwarding.apply();

        }else{
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

#define HASH_BASE 10w0
#define HASH_MAX  10w1023
#define ENTRY_SIZE 1024

register<bit<256>> (ENTRY_SIZE) fingerprint_store;
register<bit<256>> (ENTRY_SIZE) left_store;
register<bit<256>> (ENTRY_SIZE) right_store;

    bit<256> tmp_finger_value;
    bit<256> tmp_left_value;
    bit<256> tmp_right_value;

action fingerprinting() {
    meta.custom_metadata.value = hdr.chunk[1].payload;
	hash(meta.custom_metadata.fingerprint, HashAlgorithm.crc32, HASH_BASE, {meta.custom_metadata.value}, HASH_MAX);
/*	hash(meta.fingerprint[1], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[4]}, HASH_MAX);
	hash(meta.fingerprint[2], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[7]}, HASH_MAX);
	hash(meta.fingerprint[3], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[10]}, HASH_MAX);
	hash(meta.fingerprint[4], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[13]}, HASH_MAX); */

}
// Chunk[N + M], N=0, M=1 
action store_fingerprint() {
meta.custom_metadata.value = hdr.chunk[1].payload;
fingerprint_store.write( meta.custom_metadata.fingerprint, meta.custom_metadata.value);
/*fingerprint_store.write( meta.fingerprint[1], hdr.chunk[4]);
fingerprint_store.write( meta.fingerprint[2], hdr.chunk[7]);
fingerprint_store.write( meta.fingerprint[3], hdr.chunk[10]);
fingerprint_store.write( meta.fingerprint[4], hdr.chunk[13]);*/
}


action store_lvalue() {
meta.custom_metadata.left_value = hdr.chunk[0].payload;
left_store.write( meta.custom_metadata.fingerprint, meta.custom_metadata.left_value);
/*left_store.write( meta.fingerprint[1], hdr.chunk[3]);
left_store.write( meta.fingerprint[2], hdr.chunk[6]);
left_store.write( meta.fingerprint[3], hdr.chunk[9]);
left_store.write( meta.fingerprint[4], hdr.chunk[12]); */
}

action store_rvalue() {
meta.custom_metadata.right_value = hdr.chunk[2].payload;
right_store.write( meta.custom_metadata.fingerprint, meta.custom_metadata.right_value);
/*right_store.write( meta.fingerprint[1], hdr.chunk[5]);
right_store.write( meta.fingerprint[2], hdr.chunk[8]);
right_store.write( meta.fingerprint[3], hdr.chunk[11]);
right_store.write( meta.fingerprint[4], hdr.chunk[14]);*/
}


action st_retrieval() {
fingerprint_store.read(tmp_finger_value, meta.custom_metadata.fingerprint);
/*fignerprint_store.read(tmp_finger_value[1], meta.fingerprint[1]);
fignerprint_store.read(tmp_finger_value[2], meta.fingerprint[2]);
fignerprint_store.read(tmp_finger_value[3], meta.fingerprint[3]);
fignerprint_store.read(tmp_finger_value[4], meta.fingerprint[4]);*/
}


action lst_retrieval() {
left_store.read(tmp_left_value, meta.custom_metadata.fingerprint);
/*left_store.read(tmp_left_value[1], meta.fingerprint[1]);
left_store.read(tmp_left_value[2], meta.fingerprint[2]);
left_store.read(tmp_left_value[3], meta.fingerprint[3]);
left_store.read(tmp_left_value[4], meta.fingerprint[4]);*/
}

action rst_retrieval() {
right_store.read(tmp_right_value, meta.custom_metadata.fingerprint);
/*left_store.read(tmp_left_value[1], meta.fingerprint[1]);
left_store.read(tmp_left_value[2], meta.fingerprint[2]);
left_store.read(tmp_left_value[3], meta.fingerprint[3]);
left_store.read(tmp_left_value[4], meta.fingerprint[4]);*/
}

action tokenization0() {

hdr.chunk[0].setInvalid();
hdr.token[0].setValid();
hdr.token[0].bitmap1 = 1;
hdr.token[0].index = meta.custom_metadata.fingerprint;

}
action tokenization1() {

hdr.chunk[1].setInvalid();
hdr.token[1].setValid();
hdr.token[1].bitmap2 = 0;
hdr.token[1].index = meta.custom_metadata.fingerprint;

}
action tokenization2() {

hdr.chunk[2].setInvalid();
hdr.token[2].setValid();
hdr.token[2].bitmap3 = 0;
hdr.token[2].index = meta.custom_metadata.fingerprint;

}
apply{

    
    fingerprinting();
    store_fingerprint();
    store_lvalue();
    store_rvalue();
    st_retrieval(); 

    if( tmp_finger_value == meta.custom_metadata.value) {
        //lst_retrieval('0');
        tokenization1();
        rst_retrieval();
        lst_retrieval();           
        if ( tmp_left_value == meta.custom_metadata.left_value){
        tokenization0();}
        if ( tmp_right_value == meta.custom_metadata.right_value){
        tokenization2();}
            
            
            
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
        packet.emit(hdr.chunk[0]);
        packet.emit(hdr.token[0]);
        packet.emit(hdr.chunk[1]);
        packet.emit(hdr.token[1]);
        packet.emit(hdr.chunk[2]);
        packet.emit(hdr.token[2]);
    /*  packet.emit(hdr.chunk[3]);
        packet.emit(hdr.token[3]);
        packet.emit(hdr.chunk[4]);
        packet.emit(hdr.token[4]);
        packet.emit(hdr.chunk[5]);
        packet.emit(hdr.token[5]);
        packet.emit(hdr.chunk[6]);
        packet.emit(hdr.token[6]);
        packet.emit(hdr.chunk[7]);
        packet.emit(hdr.token[7]);
        packet.emit(hdr.chunk[8]);
        packet.emit(hdr.token[8]);
        packet.emit(hdr.chunk[9]);
        packet.emit(hdr.token[9]);
        packet.emit(hdr.chunk[10]);
        packet.emit(hdr.token[10]);
        packet.emit(hdr.chunk[11]);
        packet.emit(hdr.token[11]);
        packet.emit(hdr.chunk[12]);
        packet.emit(hdr.token[12]);
        packet.emit(hdr.chunk[13]);
        packet.emit(hdr.token[13]);*/
        

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
