
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser Parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
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
        } // This part will be changed
    }

}
