control fingerprinting(inout headers hdr, 
		       inout metadata meta,
		       inout standard_metadata_t standard_metadata) {


//IMPLEMENTATION: FIXED Chunking / Fingerprinting and FIXED MATCHING

//#define HASH_BASE 16w0
//#define HASH_MAX  16w65535

#define HASH_BASE 10w0
#define HASH_MAX  10w1023
#define ENTRY_SIZE 1024

register<256> (ENTRY_SIZE) fingerprint_store;
register<256> (ENTRY_SIZE) left_store;
register<256> (ENTRY_SIZE) right_store;



action fingerprinting() {

	hash(meta.fingerprint[0], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[1]}, HASH_MAX)
	hash(meta.fingerprint[1], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[4]}, HASH_MAX)
	hash(meta.fingerprint[2], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[7]}, HASH_MAX)
	hash(meta.fingerprint[3], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[10]}, HASH_MAX)
	hash(meta.fingerprint[4], HashAlgorithm.crc32, HASH_BASE, {hdr.chunk[13]}, HASH_MAX)

}
// Chunk[N + M], N=0, M=1 
action store_fingerprint() {

fingerprint_store.write( meta.fingerprint[0], hdr.chunk[0]);
fingerprint_store.write( meta.fingerprint[1], hdr.chunk[4]);
fingerprint_store.write( meta.fingerprint[2], hdr.chunk[7]);
fingerprint_store.write( meta.fingerprint[3], hdr.chunk[10]);
fingerprint_store.write( meta.fingerprint[4], hdr.chunk[13]);
}

action store_lvalue() {

//left_store.write( meta.fingerprint[0], hdr.chunk[0]);
left_store.write( meta.fingerprint[1], hdr.chunk[3]);
left_store.write( meta.fingerprint[2], hdr.chunk[6]);
left_store.write( meta.fingerprint[3], hdr.chunk[9]);
left_store.write( meta.fingerprint[4], hdr.chunk[12]);
}

action store_rvalue() {

right_store.write( meta.fingerprint[0], hdr.chunk[2]);
right_store.write( meta.fingerprint[1], hdr.chunk[5]);
right_store.write( meta.fingerprint[2], hdr.chunk[8]);
right_store.write( meta.fingerprint[3], hdr.chunk[11]);
right_store.write( meta.fingerprint[4], hdr.chunk[14]);
}


action st_retrieval(bit<3> a_index) {

fignerprint_store.read(tmp_finger_value[a_index], meta.fingerprint[a_index]);
/*fignerprint_store.read(tmp_finger_value[1], meta.fingerprint[1]);
fignerprint_store.read(tmp_finger_value[2], meta.fingerprint[2]);
fignerprint_store.read(tmp_finger_value[3], meta.fingerprint[3]);
fignerprint_store.read(tmp_finger_value[4], meta.fingerprint[4]);*/
}

l
action lst_retrieval(bit<3> b_index) {

left_store.read(tmp_left_value[b_index], meta.fingerprint[b_index]);
/*left_store.read(tmp_left_value[1], meta.fingerprint[1]);
left_store.read(tmp_left_value[2], meta.fingerprint[2]);
left_store.read(tmp_left_value[3], meta.fingerprint[3]);
left_store.read(tmp_left_value[4], meta.fingerprint[4]);*/
}

action rst_retrieval(bit<3> c_index) {

left_store.read(tmp_left_value[c_index], meta.fingerprint[c_index]);
/*left_store.read(tmp_left_value[1], meta.fingerprint[1]);
left_store.read(tmp_left_value[2], meta.fingerprint[2]);
left_store.read(tmp_left_value[3], meta.fingerprint[3]);
left_store.read(tmp_left_value[4], meta.fingerprint[4]);*/
}

action tokenization(bit<4> d_index, bit<3> e_index) {

hdr.chunk[d_index].setInValid();
hdr.token[d_index].setValid();
hdr.token[d_index].bitmap1 = '';
hdr.token[d_index].bitmap2 = '';
hdr.token[d_index].bitmap3 = '';
hdr.token[d_index].index = meta.fingerprint[e_index];

}

apply{
    bit<256> tmp_finger_value[5];
    bit<256> tmp_left_value[5];
    bit<256> tmp_right_value[5];
    
    fingerprinting();

    st_retrieval('0'); 
    if( tmp_finger_value[0] == hdr.chunk[0]) {
        //lst_retrieval('0');
        rst_retrieval('0');           
        token();
        if ( tmp_rigt_value[1] == hdr.chunk[1] ){
        
            
            
            
        }
    }else{

        store_fingerprint();
        store_lvalue();
        store_rvalue();
    

    }

    if( tmp_finger_value[4] == hdr.chunk[4]) {
        
        action1
        action2 
        action3

        if ( tmp_left_value[3] == hdr.chunk[3]){


        }
        if ( tmp_rigt_value[5] == hdr.chunk[5] ){
        
            action1
            action2
        }

    }

    if( tmp_finger_value[7] == hdr.chunk[7]) {
        
        action1
        action2 
        action3

        if ( tmp_left_value[6] == hdr.chunk[6]){


        }
        if ( tmp_rigt_value[8] == hdr.chunk[8] ){
        
            action1
            action2
        }

    }

    if( tmp_finger_value[10] == hdr.chunk[10]) {
        
        action1
        action2 
        action3

        if ( tmp_left_value[9] == hdr.chunk[9]){


        }
        if ( tmp_rigt_value[11] == hdr.chunk[11] ){
        
            action1
            action2
        }

    }

    if( tmp_finger_value[13] == hdr.chunk[13]) {
        
        action1
        action2 
        action3

        if ( tmp_left_value[12] == hdr.chunk[12]){


        }
        if ( tmp_rigt_value[14] == hdr.chunk[14] ){
        
            action1
            action2
        }

    }


}





//fingerprint store
