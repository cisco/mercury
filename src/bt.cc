// bt.cc

#include <array>
#include "libmerc/bittorrent.h"

template <size_t N>
datum get_datum(const std::array<uint8_t, N> &a) {
    datum tmp{a.data(), a.data() + a.size()};
    return tmp;
}

// class acceptor accepts and ignores a single character, setting d to
// null if the expected character is not found
//
template <uint8_t c>
class acceptor {
public:
    acceptor(datum &d) {
        d.accept(c);
    }
};

template <uint8_t c>
class accept_up_to : public datum {
public:
    accept_up_to(datum &d) {
        if (d.is_null()) {
            return;
        }
        this->data = d.data;
        while (d.is_not_empty()) {
            uint8_t tmp;
            d.lookahead_uint8(&tmp);
            if (tmp != c) {
                d.skip(1);
            } else {
                break;
            }
        }
        this->data_end = d.data;
    }
};

template <size_t N>
struct literal_string {
    literal_string(const std::array<uint8_t, N> & ) {
        // for (const auto &c : characters) {
        //     d.accept(c);
        // }
    }
};

constexpr std::array<uint8_t, 3> GET{'G', 'E', 'T'};

literal_string<3> tmp({'G', 'E', 'T'});

// class lit is a literal string of characters
//
template <size_t N>
class lit {
public:
    lit(datum &d, const std::array<uint8_t, N> &a) {
        for (const auto &c : a) {
            d.accept(c);
        }
    }
};

class uppercase : public datum {
public:
    uppercase(datum &d) {
        if (d.is_null()) {
            return;
        }
        this->data = d.data;
        while (d.is_not_empty()) {
            uint8_t tmp;
            d.lookahead_uint8(&tmp);
            if (::isupper(tmp)) {
                d.skip(1);
            } else {
                break;
            }
        }
        this->data_end = d.data;
    }
};

using space = acceptor<' '>;

class http_request_line {
    uppercase method;
    space sp1;
    accept_up_to<' '> uri;
    space sp2;
    accept_up_to<'\r'> version;
    lit<2> crlf;

public:
    http_request_line(datum &d) :
        method{d},
        sp1{d},
        uri{d},
        sp2{d},
        version{d},
        crlf{d, { '\r', '\n' }}
    { }

    void print(FILE *f) const {
        fprintf(f, "method:  ");  method.fprint(f); fputc('\n', f);
        fprintf(f, "uri:     ");     uri.fprint(f); fputc('\n', f);
        fprintf(f, "version: "); version.fprint(f); fputc('\n', f);
    }
};

class http_headers : public datum {

public:
    http_headers(datum &d) : datum{d} { }

    void print(FILE *f) const {
        datum tmp{*this};
        while (tmp.is_not_empty()) {
            accept_up_to<'\r'> header{tmp};
            lit<2> crlf{tmp, { '\r', '\n' }};
            if (!header.is_not_empty()) {
                break;
            }
            fprintf(f, "header:  ");  header.fprint(f); fputc('\n', f);
        }
    }
};

class http_request {
    http_request_line request_line;
    http_headers headers;
public:
    http_request(datum &d) : request_line{d}, headers{d} { }

    void print(FILE *f) const {
        request_line.print(f);
        headers.print(f);
    }
};

//struct tuple<T, Ts...> : tuple<Ts...> {
//  tuple(T t, Ts... ts) : tuple<Ts...>(ts...), tail(t) {}
//
//  T tail;
//};

template <class... Ts> struct literal {};

template <class T, class... Ts>
class literal<T, Ts...> : literal<Ts...> {
    T tail;
public:
    literal(T t, Ts... ts) : literal<Ts...>(ts...), tail(t) {}
};

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

#include "hex.h"

//auto x = 0X1102030405060708abcdef_hexarr;

auto http_req2 = 0x474554202f20485454502f312e310d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a486f73743a20736572766963652e627269676874636c6f75642e636f6d0d0a436f6e74656e742d4c656e6774683a203535310d0a582d494d466f7277617264733a2032300d0a5669613a20312e312072747031302d646d7a2d7773612d322e636973636f2e636f6d3a38302028436973636f2d5753412f58290d0a582d466f727761726465642d466f723a2031302e38332e35302e3234370d0a0d0a3c3f427269676874436c6f75642076657273696f6e3d626361702f312e313f3e3c626361703e3c7365716e756d3e32373c2f7365716e756d3e3c656e63727970742d747970653e656e63727970742d76313c2f656e63727970742d747970653e364441454338313936414341354441343631334643364237344535444535453035363231424132303643353145313838384139353535433444323930413239443431344644463941304237413144343633453534364636374637344531433231454430323833393644333443314232463734333144414532364235433035373835373138363843333443373638413641453345443445323441363834444445394630384141424246464331433735454136433432423232463243303644303438343041434332384546434631374135353945433237323038323635383838313431433446394336393046444238333135343243354335303241433634413939434635314536464245393438314538373632353130303431393237343531394241363346394138363439374245383538304541383037323830413043383738333635443544313033304430304135433537303646364330434430433841434444304537343344334633313343343330324242313334394341383042343530343642413730383834323333383632453736414436353532463541333538433732393833333837393737384231354134433444343830433630393034373945423438333c2f626361703e_hex;

int main() {

    literal<char, char, char> abc('G', 'E', 'T');

    const unsigned char p1[] = "i357e";
    datum d1{p1, p1+strlen((char *)p1)};
    bencoding::bint b1(d1);
    printf("'%s' has value %ld\n", (char *)p1, b1.value());

    std::array<uint8_t, 4> p2{ 'i', '8', '9', 'e' };
    datum d2 = get_datum(p2);
    bencoding::bint b2(d2);
    printf("'%.*s' has value %ld\n", (int)p2.size(), (char *)p2.data(), b2.value());

    std::array<uint8_t, 6> p3{ '4', ':', 's', 'p', 'a', 'm' };
    datum d3 = get_datum(p3);
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
    const unsigned char http_req[] = "GET / HTTP/1.1\r\nHeader: example\r\nHeader2: example2\r\n\r\n";
    datum http_data{http_req, http_req+strlen((char *)http_req)};
    http_data.fprint(stdout); fputc('\n', stdout);

    http_request req{http_data};
    req.print(stdout);

    datum http_data2{(const uint8_t *)http_req2.data(), (const uint8_t *)http_req2.data()+http_req2.size()};
    http_data2.fprint(stdout); fputc('\n', stdout);

    http_request req2{http_data2};
    req2.print(stdout);

    return 0;
}

