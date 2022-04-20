// bt.cc

#include <array>
#include "libmerc/bittorrent.h"
#include "hex.h"


/*

  Creating a packet parser using class datum

  1.  Define a class with a single constructor that accepts a 'datum &' argument.

  2.  The class should only have private data members, not public ones.

  3.  The data members should represent the data features of interest
  in the packet, in the order that the appear in the packet.

  4.  In the constructor, the data members in the initializer list
  should appear in the same order as in their declaration.

  Creating a new protocol that is connected into packet recognition
  and processing (pkt_proc/proto_ident)

  1.  Create a new class for each message in the protocol that you
  want to recognize and process.  It should be a subclass of
  tcp_base_protocol.  (TODO: rename that class to base_protocol).

  2.  Define an implementation of is_not_empty() and write_json()
  appropriate for your protocol.

  3.  If the protocol can be fingerprinted, implement a compute_fingerprint() function.

  4.  If the protocol fingerprint can be analyzed, implement a do_analysis() function.

  5.  Create a static constexpr mask_and_value<N> that can be used to
  identify the new protocol from its initial N bytes.  It may be necessary
  to create more than one matcher.  (TODO: describe how to determine a mask and value
  using the strings program, and/or create a new program to do that.)

  6. For each new protocol class defined in step 1, add an entry in
  the appropriate place in the traffic_selector class, that will
  install the matchers in the packet identification function.
  Note that the order matters, especially for protocols like QUIC
  that have ambiguous formats.

*/



auto bt_handshake = 0x13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea812fcd6a3563e3be40c1d1_hex;

auto bt_handshake_rep = 0x13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea81d93985fa70778bf0ca8c0000002d140064313a65693065313a6d6465313a7069343733303965313a7631343ab5546f7272656e7420312e362e31650000003605ffffeffefff7bffff7ffffbbffffffffffdfffff7ffdffbfffffffbfffff77fffbfffeff6fff7ffffffeeff7fffffffdffffffeffc00000005040000008a0000000504000000a000000005040000005900000005040000015c0000000504000001300000000504000001200000000504000001050000000504000000440000000504000000d90000000504000000ae00000005040000017e0000000504000001530000000504000001230000000504000000f000000005040000002c00000005040000011700000005040000001300000005040000003100000005040000014f0000000504000000b900000005040000019b00000005040000005d0000000504000000f400000005040000001f_hex;


// cow_spam is an example of a benconding dictionary
//
// note: key_and_value members MUST have their keys in increasing
// alphabetical order
//
class cow_spam {
    acceptor<'d'> d_acceptor;
    bencoding::key_and_value<bencoding::byte_string> cow;
    bencoding::key_and_value<bencoding::byte_string> spam;
    acceptor<'e'> e_acceptor;

public:

    cow_spam(datum &d) : d_acceptor{d}, cow{d}, spam{d}, e_acceptor{d} {  }

    void fprint(FILE *f) const {
        fprintf(f, "cow: "); cow.value().fprint(f);   fputc('\n', f);
        fprintf(f, "spam: "); spam.value().fprint(f);  fputc('\n', f);
    }
};


auto http_req2 = 0x474554202f20485454502f312e310d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a486f73743a20736572766963652e627269676874636c6f75642e636f6d0d0a436f6e74656e742d4c656e6774683a203535310d0a582d494d466f7277617264733a2032300d0a5669613a20312e312072747031302d646d7a2d7773612d322e636973636f2e636f6d3a38302028436973636f2d5753412f58290d0a582d466f727761726465642d466f723a2031302e38332e35302e3234370d0a0d0a3c3f427269676874436c6f75642076657273696f6e3d626361702f312e313f3e3c626361703e3c7365716e756d3e32373c2f7365716e756d3e3c656e63727970742d747970653e656e63727970742d76313c2f656e63727970742d747970653e364441454338313936414341354441343631334643364237344535444535453035363231424132303643353145313838384139353535433444323930413239443431344644463941304237413144343633453534364636374637344531433231454430323833393644333443314232463734333144414532364235433035373835373138363843333443373638413641453345443445323441363834444445394630384141424246464331433735454136433432423232463243303644303438343041434332384546434631374135353945433237323038323635383838313431433446394336393046444238333135343243354335303241433634413939434635314536464245393438314538373632353130303431393237343531394241363346394138363439374245383538304541383037323830413043383738333635443544313033304430304135433537303646364330434430433841434444304537343344334633313343343330324242313334394341383042343530343642413730383834323333383632453736414436353532463541333538433732393833333837393737384231354134433444343830433630393034373945423438333c2f626361703e_hex;

int main() {

    datum bittorrent_handshake_data{(const uint8_t *)bt_handshake.data(), (const uint8_t *)bt_handshake.data()+bt_handshake.size()};
    bittorrent_handshake handshake{bittorrent_handshake_data};
    handshake.fprint(stdout); fputc('\n', stdout);

    datum bittorrent_handshake_rep_data{(const uint8_t *)bt_handshake_rep.data(), (const uint8_t *)bt_handshake_rep.data()+bt_handshake_rep.size()};
    bittorrent_handshake handshake_rep{bittorrent_handshake_rep_data};
    handshake_rep.fprint(stdout); fputc('\n', stdout);

    const unsigned char p1[] = "i357e";
    datum d1{p1, p1+strlen((char *)p1)};
    bencoding::bint b1(d1);
    printf("'%s' has value %ld\n", (char *)p1, b1.value());

    std::array<uint8_t, 4> p2{ 'i', '8', '9', 'e' };
    datum d2{p2};
    bencoding::bint b2(d2);
    printf("'%.*s' has value %ld\n", (int)p2.size(), (char *)p2.data(), b2.value());

    std::array<uint8_t, 6> p3{ '4', ':', 's', 'p', 'a', 'm' };
    datum d3{p3};
    bencoding::byte_string b3(d3);
    printf("'%.*s' has value ", (int)p3.size(), (char *)p3.data());
    b3.value().fprint(stdout);
    fputc('\n', stdout);

    const unsigned char p4[] = "d3:cow3:moo4:spam4:eggse"; // represents the dictionary { "cow" => "moo", "spam" => "eggs" }
    datum d4{p4, p4+strlen((char *)p4)};
    cow_spam cs(d4);
    cs.fprint(stdout);

    // test literals
    //
    const unsigned char http_req[] = "VERSION-CONTROL / HTTP/1.1\r\nHeader: example\r\nHeader2: example2\r\n\r\n";
    datum http_data{http_req, http_req+strlen((char *)http_req)};
    http_data.fprint(stdout); fputc('\n', stdout);

    http::request req{http_data};
    req.print(stdout);

    datum http_data2{(const uint8_t *)http_req2.data(), (const uint8_t *)http_req2.data()+http_req2.size()};
    http_data2.fprint(stdout); fputc('\n', stdout);

    http::request req2{http_data2};
    req2.print(stdout);

    return 0;
}

