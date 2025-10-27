// tacacs_decrypt.cpp
//
// compilation: g++ -Wall -DSSLNEW -Wno-deprecated-declarations tacacs_decrypt.cpp -lcrypto -o tacacs_decrypt

#include "libmerc/datum.h"
#include "libmerc/crypto_engine.h"
#include "libmerc/tacacs.hpp"


/// decrypt the (first 16 bytes of the) ciphertext and return the
/// (first 16 bytes of the) corresponding plaintext
///
std::array<uint8_t, 16> tacacs_plus_decrypt(encoded<uint32_t> session_id,
                                            const std::string &key,
                                            encoded<uint8_t> version,
                                            encoded<uint8_t> seq_no,
                                            std::array<uint8_t, 16> ciphertext)
{
    std::array<uint8_t, 16> plaintext;


    // marshall inputs into md5 input buffer
    //
    data_buffer<64> md5_input;
    md5_input << session_id
              << datum{key}
              << version
              << seq_no;

    if (md5_input.contents().is_not_null()) {

        // compute pseudorandom pad (pseudo_pad) as per RFC 8907,
        // Section 3.7:
        //
        //    MD5_i = / md5(session_id, key, version, seq_no)            for i=1
        //            \ md5(session_id, key, version, seq_no, MD5_{i-1}) for i>1
        //
        //
        hasher md5{"md5"};
        data_buffer<16> pseudo_pad;
        md5.hash_buffer(md5_input.contents().data, md5_input.readable_length(), pseudo_pad.data, pseudo_pad.writeable_length());
        pseudo_pad.data += 16;

        // XOR pseudo_pad and ciphertext to get plaintext
        for (size_t i=0; i<16; i++) {
            plaintext[i] = ciphertext[i] ^ pseudo_pad.contents().data[i];
        }

    }

    return plaintext;
}

int main(int argc, char *argv[]) {

    encoded<uint32_t> session_id = hton<uint32_t>(0x6d0e1631);
    std::string key = "1234";
    encoded<uint8_t> version = 0xc0;
    encoded<uint8_t> seq_no = 0x01;
    std::array<uint8_t, 16> ciphertext{0x57, 0x39, 0x08, 0xbd, 0x8e, 0xd2, 0xc2, 0x8e, 0xfa, 0xff, 0x1b, 0xf0, 0x0d, 0x07, 0x57, 0x8a}; // 9a
    std::array<uint8_t, 16> plaintext = tacacs_plus_decrypt(session_id, key, version, seq_no, ciphertext);

    fputs("plaintext: ", stdout);
    datum{plaintext}.fprint_hex(stdout); fputc('\n', stdout);

    std::array<uint8_t, 16> expected_plaintext{0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x05, 0x00, 0x74, 0x74, 0x79, 0x30, 0x61, 0x73, 0x79, 0x6e}; // 0x63
    if (plaintext != expected_plaintext) {
        fputs("error: expected plaintext: ", stdout);
        datum{expected_plaintext}.fprint_hex(stdout); fputc('\n', stdout);
    }

    auto hcat = tacacs::get_hashcast_string(ntoh(session_id),
                                             version,
                                             seq_no,
                                             datum{ciphertext});
    if (hcat.contents().is_not_empty()) {
        hcat.contents().fprint(stdout); fputc('\n', stdout);
    }

    return 0;
}
