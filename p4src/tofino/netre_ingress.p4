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
typedef bit<32> chunk_size_1;
typedef bit<8> chunk_size_2;
typedef bit<40> chunk_size_3;
typedef bit<16> token_size;




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

header chunk_t {
    chunk_size_1 chunk_1; //32
    chunk_size_2 chunk_2;
    chunk_size_1 chunk_3;
    chunk_size_2 chunk_4; //8
}

header token_t {
    token_size token_index; //16
}

header tre_shim_t {
    bit<16> srcSwitchID;
    bit<16> dstSwitchID;
    bit<16> bitmap;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct ig_tre_metadata_t {
    bit<1> mark;
}

struct custom_metadata_t {
    token_size idx;
    chunk_size_1 tmp_size_1;
    chunk_size_2 tmp_size_2;
    chunk_size_1 value_sub_1;
    chunk_size_2 value_sub_2;
    chunk_size_1 val;
    chunk_size_1 val2;
    chunk_size_3 val3;


}

struct metadata_t {
    ig_tre_metadata_t ig_tre;

}

struct empty_header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    tre_shim_t tre_shim;
    chunk_t[MAX_LEN] chunk;
    token_t[MAX_LEN] token;
}

struct empty_metadata_t {
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
    }
    action tre_enable() {
        ig_tm_md.bypass_egress = 0;
    }
    action tre_bypass() {
        ig_tm_md.bypass_egress = 1;
    }


    table set_egress_table {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            set_egress();
        }
        const entries = {
            172 : set_egress(173);
        }
    }

    table set_config_table{
        key = {
            ig_md.ig_tre.mark: exact;
        }
        actions = {
            tre_enable();
            tre_bypass();
        }
        const entries = {
            1 : tre_enable();
            0 : tre_bypass();
        }
    }

    apply {
        ig_md.ig_tre.mark = 1; //set mark = 1, if you want to perform NETRE
        if (hdr.ipv4.isValid()){
            set_egress_table.apply();
            set_config_table.apply();
        }
    }
}

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
        transition parse_chunk_0;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_chunk_0;
    }

    state parse_chunk_0 {
        pkt.extract(hdr.chunk[0]);
        transition parse_chunk_1;
    }

    state parse_chunk_1 {
        pkt.extract(hdr.chunk[1]);
        transition parse_chunk_2;
    }

    state parse_chunk_2 {
        pkt.extract(hdr.chunk[2]);
        transition parse_chunk_3;
    }

    state parse_chunk_3 {
        pkt.extract(hdr.chunk[3]);
        transition parse_chunk_4;
    }

    state parse_chunk_4 {
        pkt.extract(hdr.chunk[4]);
        transition parse_chunk_5;
    }

    state parse_chunk_5 {
        pkt.extract(hdr.chunk[5]);
        transition parse_chunk_6;
    }

    state parse_chunk_6 {
        pkt.extract(hdr.chunk[6]);
        transition parse_chunk_7;
    }

    state parse_chunk_7 {
        pkt.extract(hdr.chunk[7]);
        transition parse_chunk_8;
    }

    state parse_chunk_8 {
        pkt.extract(hdr.chunk[8]);
        transition parse_chunk_9;
    }

    state parse_chunk_9 {
        pkt.extract(hdr.chunk[9]);
        transition parse_chunk_10;
    }

    state parse_chunk_10 {
        pkt.extract(hdr.chunk[10]);
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
        pkt.emit(hdr.tre_shim);
        pkt.emit(hdr.chunk[0]);
        pkt.emit(hdr.token[0]);
        pkt.emit(hdr.chunk[1]);
        pkt.emit(hdr.token[1]);
        pkt.emit(hdr.chunk[2]);
        pkt.emit(hdr.token[2]);
        pkt.emit(hdr.chunk[3]);
        pkt.emit(hdr.token[3]);
        pkt.emit(hdr.chunk[4]);
        pkt.emit(hdr.token[4]);
        pkt.emit(hdr.chunk[5]);
        pkt.emit(hdr.token[5]);
        pkt.emit(hdr.chunk[6]);
        pkt.emit(hdr.token[6]);
        pkt.emit(hdr.chunk[7]);
        pkt.emit(hdr.token[7]);
        pkt.emit(hdr.chunk[8]);
        pkt.emit(hdr.token[8]);
        pkt.emit(hdr.chunk[9]);
        pkt.emit(hdr.token[9]);
        pkt.emit(hdr.chunk[10]);
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
        hdr.chunk[##i##].chunk_1, \
        hdr.chunk[##i##].chunk_2, \
        hdr.chunk[##i##].chunk_3, \
        hdr.chunk[##i##].chunk_4 \
    }

    #define TEST_REG(i) \
        Hash<bit<16>> (HashAlgorithm_t.CRC16) hash##i; \
        Register<chunk_size_1, bit<32>>(32w65536) register_##i##_part_1; \
        RegisterAction<chunk_size_1, bit<32>, chunk_size_1>(register_##i##_part_1) reg_##i##_part_1_action = { \
            void apply(inout chunk_size_1 value, out chunk_size_1 read_value){ \
                read_value = value; \
                if (read_value != hdr.chunk[##i##].chunk_1 || read_value == 0) { \
                    value = hdr.chunk[##i##].chunk_1; \
                    } \
            } \
        }; \
        Register<chunk_size_2, bit<32>>(32w65536) register_##i##_part_2; \
        RegisterAction<chunk_size_2, bit<32>, chunk_size_2>(register_##i##_part_2) reg_##i##_part_2_action = { \
            void apply(inout chunk_size_2 value, out chunk_size_2 read_value){ \
                read_value = value; \
                if (read_value != hdr.chunk[##i##].chunk_2 || read_value == 0) { \
                    value = hdr.chunk[##i##].chunk_2; \
                    } \
            } \
        }; \
        Register<chunk_size_1, bit<32>>(32w65536) register_##i##_part_3; \
        RegisterAction<chunk_size_1, bit<32>, chunk_size_1>(register_##i##_part_3) reg_##i##_part_3_action = { \
            void apply(inout chunk_size_1 value, out chunk_size_1 read_value){ \
                read_value = value; \
                if (read_value != hdr.chunk[##i##].chunk_3 || read_value == 0) { \
                    value = hdr.chunk[##i##].chunk_3; \
                    } \
            } \
        }; \
        Register<chunk_size_2, bit<32>>(32w65536) register_##i##_part_4; \
        RegisterAction<chunk_size_2, bit<32>, chunk_size_2>(register_##i##_part_4) reg_##i##_part_4_action = { \
            void apply(inout chunk_size_2 value, out chunk_size_2 read_value){ \
                read_value = value; \
                if (read_value != hdr.chunk[##i##].chunk_4 || read_value == 0) { \
                    value = hdr.chunk[##i##].chunk_4; \
                    } \
            } \
        }; \
        action register_action##i() { \
             eg_md.custom_metadata.idx = hash##i.get(CHUNK_HASH_FIELDS(##i##)); \
             eg_md.custom_metadata.tmp_size_1 = reg_##i##_part_1_action.execute((bit<32>)eg_md.custom_metadata.idx); \
             eg_md.custom_metadata.value_sub_1 = eg_md.custom_metadata.tmp_size_1 - hdr.chunk[##i##].chunk_1;\
        }\
        action register_action_1_##i() {\
             reg_##i##_part_2_action.execute((bit<32>)eg_md.custom_metadata.idx); \
        } \
        action register_action_2_##i() {\
             reg_##i##_part_3_action.execute((bit<32>)eg_md.custom_metadata.idx); \
        } \
        action register_action_3_##i() {\
             eg_md.custom_metadata.tmp_size_2 = reg_##i##_part_4_action.execute((bit<32>)eg_md.custom_metadata.idx); \
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



    #define CACHE_CHECK(i, j) \
        action cache_hit##i##(bit<4> idx, bit<16> value) { \
            hdr.tre_shim.bitmap = hdr.tre_shim.bitmap + value; \
            hdr.token[##i##].token_index = eg_md.custom_metadata.idx; \
            hdr.chunk[##i##].setInvalid(); \
        } \
        action cache_miss##i##(bit<4> idx) { \
            hdr.token[##i##].setInvalid(); \
        } \
        table cache_check_##i { \
            key = { \
                eg_md.custom_metadata.value_sub_1: exact; \
            } \
            actions = { \
                cache_hit##i##(); \
                cache_miss##i##(); \
            } \
            default_action = cache_miss##i##(##i##); \
            const entries = { \
                (0) : cache_hit##i##(##i##, ##j##); \
            } \
        }

    CACHE_CHECK(0, 1)
    CACHE_CHECK(1, 2)
    CACHE_CHECK(2, 4)
    CACHE_CHECK(3, 8)
    CACHE_CHECK(4, 16)
    CACHE_CHECK(5, 32)
    CACHE_CHECK(6, 64)
    CACHE_CHECK(7, 128)
    CACHE_CHECK(8, 256)
    CACHE_CHECK(9, 512)
    CACHE_CHECK(10, 1024)

    action initial_setup() {
        hdr.tre_shim.setValid();
        hdr.tre_shim.bitmap = 0;
        hdr.tre_shim.srcSwitchID = 0;
        hdr.tre_shim.dstSwitchID = 0;

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
        cache_check_0.apply();

        register_action1();
        register_action_1_1();
        register_action_2_1();
        register_action_3_1();
        cache_check_1.apply();

        register_action2();
        register_action_1_2();
        register_action_2_2();
        register_action_3_2();
        cache_check_2.apply();

        register_action3();
        register_action_1_3();
        register_action_2_3();
        register_action_3_3();
        cache_check_3.apply();

        register_action4();
        register_action_1_4();
        register_action_2_4();
        register_action_3_4();
        cache_check_4.apply();

        register_action5();
        register_action_1_5();
        register_action_2_5();
        register_action_3_5();
        cache_check_5.apply();

        register_action6();
        register_action_1_6();
        register_action_2_6();
        register_action_3_6();
        cache_check_6.apply();

        register_action7();
        register_action_1_7();
        register_action_2_7();
        register_action_3_7();
        cache_check_7.apply();

        register_action8();
        register_action_1_8();
        register_action_2_8();
        register_action_3_8();
        cache_check_8.apply();

        register_action9();
        register_action_1_9();
        register_action_2_9();
        register_action_3_9();
        cache_check_9.apply();

        register_action10();
        register_action_1_10();
        register_action_2_10();
        register_action_3_10();
        cache_check_10.apply();

    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
