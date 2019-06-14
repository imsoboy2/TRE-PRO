/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include <headers.p4>
#include <parser.p4>
#include <ip_forward.p4>
#include <fingerprinting.p4>
//#include <cache.p4>
#include <checksum.p4>


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
    


    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0){

        forward();

        }else{
        Mark_to_drop();
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
   
    }
    apply {
        fingerprinting();    
        send_frame();
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
        packet.emit(hdr.chunk[3]);
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
        packet.emit(hdr.token[13]);
        packet.emit(hdr.chunk[14]);
        packet.emit(hdr.token[14]);

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
