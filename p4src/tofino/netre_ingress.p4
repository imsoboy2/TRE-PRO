#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define MAX_LEN 11

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
const ip_protocol_t IP_PROTOCOLS_SHIM_TCP = 77;
const ip_protocol_t IP_PROTOCOLS_SHIM_UDP = 78;

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

// header chunk_t {
//     bit<32> chunk_payload;
// }


header chunk_1_t {
    bit<32> chun1;
    bit<32> chun2;
}
header chunk_2_t {
    bit<8> chun1;
    bit<8> chun2;
}
header token_t {
    bit<16> token_index;
}

header tre_bitmap_t {
    bit<16> srcSwitchID;
    bit<16> dstSwitchID;
    bit<16> bitmap;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    // tre_bitmap_t tre_bitmap;
    // // chunk_t[MAX_LEN] chunk;
    // chunk_1_t[MAX_LEN] chunks;
    // chunk_2_t[MAX_LEN] chunks1;
    // token_t[MAX_LEN] token;
}

struct parser_metadata_t {
    bit<1> enable_tre;
    bit<1> remaining;
}

struct custom_metadata_t {
    bit<16> idx;
    bit<32> tmp;
    bit<16> idx_1;
    bit<32> tmp_1;
    bit<16> idx_2;
    bit<32> tmp_2;
    bit<32> tmp_hyeim;
    bit<8> tmp_yang;
    bit<8> tmp_yang_test;
}

struct metadata_t {

}

struct empty_header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    tre_bitmap_t tre_bitmap;
    // chunk_t[MAX_LEN] chunk;
    chunk_1_t[MAX_LEN] chunks;
    chunk_2_t[MAX_LEN] chunks1;
    token_t[MAX_LEN] token;
}

struct empty_metadata_t {
    parser_metadata_t parser_metadata;
    custom_metadata_t custom_metadata;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        // ig_md.parser_metadata.enable_tre = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

      // state parse_chunk7 {
    //     pkt.extract(hdr.chunks[7]);
    //     pkt.extract(hdr.chunks1[7]);
    //     transition accept;
    // }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
 
    action set_egress(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress = true;
    }

     action set_tre(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table switching_table {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            set_egress();
            set_tre();
        }
        const entries = {
            160 : set_tre(176);
            184 : set_egress(172);
            164 : set_egress(148);
            156 : set_egress(132);
            140 : set_egress(160);
        }
    }

    apply {
        switching_table.apply();
    }
  
}

// Empty egress parser/control blocks
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition parse_chunk0;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_chunk0;
    }

    state parse_chunk0 {
        pkt.extract(hdr.chunks[0]);
        pkt.extract(hdr.chunks1[0]);
        transition parse_chunk1;
    }

    state parse_chunk1 {
        pkt.extract(hdr.chunks[1]);
        pkt.extract(hdr.chunks1[1]);
        transition parse_chunk2;
    }

    state parse_chunk2 {
        pkt.extract(hdr.chunks[2]);
        pkt.extract(hdr.chunks1[2]);
        transition parse_chunk3;
    }

    state parse_chunk3 {
        pkt.extract(hdr.chunks[3]);
        pkt.extract(hdr.chunks1[3]);
        transition parse_chunk4;
    }

    state parse_chunk4 {
        pkt.extract(hdr.chunks[4]);
        pkt.extract(hdr.chunks1[4]);
        transition parse_chunk5;
    }

    state parse_chunk5 {
        pkt.extract(hdr.chunks[5]);
        pkt.extract(hdr.chunks1[5]);
        transition parse_chunk6;
    }

    state parse_chunk6 {
        pkt.extract(hdr.chunks[6]);
        pkt.extract(hdr.chunks1[6]);
        transition parse_chunk7;
    }

    state parse_chunk7 {
        pkt.extract(hdr.chunks[7]);
        pkt.extract(hdr.chunks1[7]);
        transition parse_chunk8;
    }

    state parse_chunk8 {
        pkt.extract(hdr.chunks[8]);
        pkt.extract(hdr.chunks1[8]);
        transition parse_chunk9;
    }

    state parse_chunk9 {
        pkt.extract(hdr.chunks[9]);
        pkt.extract(hdr.chunks1[9]);
        transition parse_chunk10;
    }

    state parse_chunk10 {
        pkt.extract(hdr.chunks[10]);
        pkt.extract(hdr.chunks1[10]);
        transition accept;
    }

}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tre_bitmap);
        pkt.emit(hdr.chunks[0]);
        pkt.emit(hdr.token[0]);
        pkt.emit(hdr.chunks[1]);
        pkt.emit(hdr.token[1]);
        pkt.emit(hdr.chunks[2]);
        pkt.emit(hdr.token[2]);
        pkt.emit(hdr.chunks[3]);
        pkt.emit(hdr.token[3]);
        pkt.emit(hdr.chunks[4]);
        pkt.emit(hdr.token[4]);
        pkt.emit(hdr.chunks[5]);
        pkt.emit(hdr.token[5]);
        pkt.emit(hdr.chunks[6]);
        pkt.emit(hdr.token[6]);
        pkt.emit(hdr.chunks[7]);
        pkt.emit(hdr.token[7]);
        pkt.emit(hdr.chunks[8]);
        pkt.emit(hdr.token[8]);
        pkt.emit(hdr.chunks[9]);
        pkt.emit(hdr.token[9]);
        pkt.emit(hdr.chunks[10]);
        pkt.emit(hdr.token[10]);
    }
}

control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {


     #define CHUNK_HASH_FIELDS(i) { \
        hdr.chunks[##i##].chun1, \
        hdr.chunks[##i##].chun2, \
        hdr.chunks1[##i##].chun1, \
        hdr.chunks1[##i##].chun2 \
    }

    #define TEST_REG(i) \
        Hash<bit<16>> (HashAlgorithm_t.CRC16) hash##i; \
        Register<bit<32>, bit<32>>(32w65536) test_reg##i; \
        RegisterAction<bit<32>, bit<32>, bit<32>>(test_reg##i) test_reg_action##i = { \
            void apply(inout bit<32> value, out bit<32> read_value){ \
                read_value = value; \
                if (read_value != hdr.chunks[##i##].chun1 || read_value == 0) { \
                    value = hdr.chunks[##i##].chun1; \
                    } \
            } \
        }; \
        Register<bit<32>, bit<32>>(32w65536) test_reg_1##i; \
        RegisterAction<bit<32>, bit<32>, bit<32>>(test_reg_1##i) test_reg_1_action##i = { \
            void apply(inout bit<32> value, out bit<32> read_value){ \
                read_value = value; \
                if (read_value != hdr.chunks[##i##].chun2 || read_value == 0) { \
                    value = hdr.chunks[##i##].chun2; \
                    } \
            } \
        }; \
           Register<bit<8>, bit<32>>(32w65536) test_reg_2##i; \
        RegisterAction<bit<8>, bit<32>, bit<8>>(test_reg_2##i) test_reg_2_action##i = { \
            void apply(inout bit<8> value, out bit<8> read_value){ \
                read_value = value; \
                if (read_value != hdr.chunks1[##i##].chun1 || read_value == 0) { \
                    value = hdr.chunks1[##i##].chun1; \
                    } \
            } \
        }; \
        Register<bit<8>, bit<32>>(32w65536) test_reg_3##i; \
        RegisterAction<bit<8>, bit<32>, bit<8>>(test_reg_3##i) test_reg_3_action##i = { \
            void apply(inout bit<8> value, out bit<8> read_value){ \
                read_value = value; \
                if (read_value != hdr.chunks1[##i##].chun2 || read_value == 0) { \
                    value = hdr.chunks1[##i##].chun2; \
                    } \
            } \
        }; \
        action register_action##i() { \
             eg_md.custom_metadata.idx = hash##i.get(CHUNK_HASH_FIELDS(##i##)); \
             eg_md.custom_metadata.tmp = test_reg_action##i.execute((bit<32>)eg_md.custom_metadata.idx); \
             eg_md.custom_metadata.tmp_hyeim = eg_md.custom_metadata.tmp - hdr.chunks[##i##].chun1;\
        }\
        action register_action_1_##i() {\
             eg_md.custom_metadata.tmp_1 = test_reg_1_action##i.execute((bit<32>)eg_md.custom_metadata.idx); \
             } \
        action register_action_2_##i() {\
             eg_md.custom_metadata.tmp_yang = test_reg_2_action##i.execute((bit<32>)eg_md.custom_metadata.idx); \
             eg_md.custom_metadata.tmp_yang_test = eg_md.custom_metadata.tmp_yang - hdr.chunks1[##i##].chun1; \
        } \
        action register_action_3_##i() {\
             test_reg_3_action##i.execute((bit<32>)eg_md.custom_metadata.idx); \
        }  

    TEST_REG(0)
    TEST_REG(1)
    TEST_REG(2)
    TEST_REG(3)
    TEST_REG(4)
    TEST_REG(5)
    TEST_REG(6)
    TEST_REG(7)
    TEST_REG(8)
    TEST_REG(9)
    TEST_REG(10)

    action initial_setup() {
        hdr.tre_bitmap.setValid();
        hdr.tre_bitmap.bitmap = 0;
        hdr.tre_bitmap.srcSwitchID = 0;
        hdr.tre_bitmap.dstSwitchID = 0;

        // ig_tm_md.ucast_egress_port = 1;
        // ig_tm_md.bypass_egress = true;

        hdr.token[0].setValid();
        hdr.token[1].setValid();
        hdr.token[2].setValid();
        hdr.token[3].setValid();
        hdr.token[4].setValid();
        hdr.token[5].setValid();
        hdr.token[6].setValid();
        hdr.token[7].setValid();
        hdr.token[8].setValid();
        hdr.token[9].setValid();
        hdr.token[10].setValid();
    }

    apply {
        initial_setup();

        
        register_action0();
        register_action_1_0();
        register_action_2_0();
        register_action_3_0();
        if ( eg_md.custom_metadata.tmp_hyeim == 0 && eg_md.custom_metadata.tmp_yang_test == 0){ // HIT
            hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 1; 
            hdr.token[0].token_index = eg_md.custom_metadata.idx;
            hdr.chunks[0].setInvalid();
        } else {
            hdr.token[0].setInvalid();
        }
        

        
        register_action1();
        register_action_1_1();
        register_action_2_1();
        register_action_3_1();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[1].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 2;
           hdr.token[1].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[1].setInvalid();
        } else {
            hdr.token[1].setInvalid();
        }
        

        
        register_action2();
        register_action_1_2();
        register_action_2_2();
        register_action_3_2();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[2].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 4;
           hdr.token[2].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[2].setInvalid();
        } else {
            hdr.token[2].setInvalid();
        } 
        

        
        register_action3();
        register_action_1_3();
        register_action_2_3();
        register_action_3_3();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[3].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 8;
           hdr.token[3].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[3].setInvalid();
        } else {
            hdr.token[3].setInvalid();
        }
        

        
        register_action4();
        register_action_1_4();
        register_action_2_4();
        register_action_3_4();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[4].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 16;
           hdr.token[4].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[4].setInvalid();
        } else {
            hdr.token[4].setInvalid();
        }
        

        
        register_action5();
        register_action_1_5();
        register_action_2_5();
        register_action_3_5();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[5].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 32;
           hdr.token[5].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[5].setInvalid();
        } else {
            hdr.token[5].setInvalid();
        }
        

        
        register_action6();
        register_action_1_6();
        register_action_2_6();
        register_action_3_6();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[6].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 64;
           hdr.token[6].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[6].setInvalid();
        } else {
            hdr.token[6].setInvalid();
        }
        

        
        register_action7();
        register_action_1_7();
        register_action_2_7();
        register_action_3_7();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[7].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 128;
           hdr.token[7].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[7].setInvalid();
        } else {
            hdr.token[7].setInvalid();
        }
        

        
        register_action8();
        register_action_1_8();
        register_action_2_8();
        register_action_3_8();
        if ( eg_md.custom_metadata.tmp == hdr.chunks[8].chun1){
           hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 128;
           hdr.token[8].token_index = eg_md.custom_metadata.idx;
           hdr.chunks[8].setInvalid();
        } else {
            hdr.token[8].setInvalid();
        }
        
        

        // register_action9();
        // register_action_1_9();
        // register_action_2_9();
        // register_action_3_9();
        // if ( ig_md.custom_metadata.tmp_1 == hdr.chunks[9].chun1){
        //    //hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 128;
        //    hdr.token[9].token_index = ig_md.custom_metadata.idx;
        //    hdr.chunks[9].setInvalid();
        // } else {
        //     hdr.token[9].setInvalid();
        // }

        // register_action10();
        // register_action_1_10();
        // register_action_2_10();
        // register_action_3_10();
        // if ( ig_md.custom_metadata.tmp_1 == hdr.chunks[10].chun1){
        //    //hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 128;
        //    hdr.token[10].token_index = ig_md.custom_metadata.idx;
        //    hdr.chunks[10].setInvalid();
        // } else {
        //     hdr.token[10].setInvalid();
        // }
        // register_action8();
        // if ( ig_md.custom_metadata.tmp_2 == hdr.chunk[8].chunk_payload){
        //    //hdr.tre_bitmap.bitmap = hdr.tre_bitmap.bitmap + 128;
        //    hdr.token[8].token_index = ig_md.custom_metadata.idx_2;
        //    hdr.chunk[8].setInvalid();
        // } else {
        //     hdr.token[8].setInvalid();
        // }
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;