#ifndef PERFECT_HASH_H
#define PERFECT_HASH_H

//Hash, displace, and compress algorithm was taken as reference
//https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.568.130&rep=rep1&type=pdf

#include <string>
#include <cstring>
#include <vector>
#include <algorithm>

template<typename T>
struct perfect_hash_entry
{
    public:
    perfect_hash_entry(const char* key, size_t key_len, T value) {
        _value = value;
        _key = key;
        _key_len = key_len;
    }

    size_t _key_len = -1;
    const char* _key = nullptr;
    uint32_t _hash = 0;

    T _value;
};

//MurmurHash By Austin Appleby https://sites.google.com/site/murmurhash/
struct murmur2_hash {

    uint32_t operator() (const char* key, size_t len, const uint32_t& res) {
        /* 'm' and 'r' are mixing constants generated offline.
        They're not really 'magic', they just happen to work well.  */

        const uint32_t m = 0x5bd1e995;
        const int r = 24;

        /* Initialize the hash to a 'random' value */

        uint32_t h = res ^ len;

        /* Mix 4 bytes at a time into the hash */

        const unsigned char * data = (const unsigned char *)key;

        while(len >= 4)
        {
            uint32_t k = *(uint32_t*)data;

            k *= m;
            k ^= k >> r;
            k *= m;

            h *= m;
            h ^= k;

            data += 4;
            len -= 4;
        }

        /* Handle the last few bytes of the input array  */

        switch(len)
        {
        case 3: h ^= data[2] << 16;
        [[fallthrough]];
        case 2: h ^= data[1] << 8;
        [[fallthrough]];
        case 1: h ^= data[0];
            h *= m;
        };

        /* Do a few final mixes of the hash to ensure the last few
        // bytes are well-incorporated.  */

        h ^= h >> 13;
        h *= m;
        h ^= h >> 15;

        return h;
    }
};

template<typename T>
struct perfect_hash {

    private:
    int64_t* _g_table;
    perfect_hash_entry<T>** _values;

    size_t _key_set_len;
    size_t _lookup_len;

    murmur2_hash hash;

    public:

    ~perfect_hash() {
        cleanup();
    }

    void cleanup() {
        delete[] _g_table;
        for(size_t i = 0; i < _key_set_len; i++){
            delete _values[i];
        }
        delete[] _values;
    }

    static inline uint32_t murmur_32_scramble(uint32_t k) {
        k *= 0xcc9e2d51;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593;
        return k;
    }

    bool contains_value(int64_t* arr, size_t len, int64_t val) {
        for(size_t i = 0; i < len; i++) {
            if(arr[i] == val)
                return true;
        }
        return false;
    }

    void create_perfect_hash_table(std::vector<perfect_hash_entry<T>>& data_set, size_t load_factor) {
        _key_set_len = data_set.size();

        _lookup_len = (load_factor * _key_set_len) / 100;

        _values = new perfect_hash_entry<T>*[_key_set_len];

        std::vector<std::vector<perfect_hash_entry<T>>> _buckets;

        for(size_t i = 0; i < _key_set_len; i++)
        {
            _values[i] = nullptr;
        }

        for(size_t i = 0; i < _lookup_len; i++)
        {
            _buckets.push_back({});
        }

        for(const auto& data : data_set)
        {
            auto tmp_indx = hash(data._key, data._key_len, 0) % _lookup_len;
            _buckets.at(tmp_indx).push_back(data);
        }
        
        std::sort(_buckets.begin(), _buckets.end(), [](const std::vector<perfect_hash_entry<T>>& rv, const std::vector<perfect_hash_entry<T>>& lv)
        {
            return rv.size() > lv.size();
        });
        
        _g_table = new int64_t[_lookup_len];
        std::fill_n(_g_table, _lookup_len, 0L);

        int64_t* pslots = nullptr;

        for(size_t indx = 0; indx < _lookup_len; indx++) {
            if(_buckets[indx].size() <= 1) break;

            auto bucket = _buckets[indx];

            uint32_t d;
            size_t item;
            d = 1;
            item = 0;

            if(pslots == nullptr)
                pslots = new int64_t[bucket.size()];

            std::fill_n(pslots, bucket.size(), 0L);
            
            while(item < bucket.size()) {

                size_t slot = hash(bucket.at(item)._key, bucket.at(item)._key_len, d) % _key_set_len;

                if(_values[slot] != nullptr || contains_value(pslots, item, slot)) {
                    d += 1;
                    if(d < 0) break;
                    item = 0;
                    
                    std::fill_n(pslots, bucket.size(), -1);
                }
                else{
                    pslots[item] = slot;
                    item += 1;
                }
            }
            if(d < 0) {
                exit(1);//TODO:: check if exit is expected
            }
            
            _g_table[hash(bucket[0]._key, bucket[0]._key_len, 0) % _lookup_len] = static_cast<int64_t>(d);
            for(size_t c = 0; c < bucket.size(); c++)
            {
                _values[pslots[c]] = new perfect_hash_entry<T>(bucket[c]);
                _values[pslots[c]]->_hash = hash(bucket[c]._key, bucket[c]._key_len, 0);
            }
        }
        delete[] pslots;

        std::vector<int64_t> free_list;
        for(size_t i = 0; i < _key_set_len; i++) {
            if(_values[i] == nullptr)
                free_list.push_back(i);
        }
                
        for(size_t b = 0; b < _lookup_len; b++) {
            auto bucket = _buckets[b];
            if(bucket.size() == 0 || bucket.size() > 1) continue;
            auto slot = free_list.back();
            free_list.pop_back();
            _g_table[hash(bucket[0]._key, bucket[0]._key_len, 0) % _lookup_len] = -slot-1;
            _values[slot] = new perfect_hash_entry<T>(bucket[0]);
            _values[slot]->_hash = hash(bucket[0]._key, bucket[0]._key_len, 0);
        }
    }

    inline T* lookup(const char* key, const size_t& key_len, bool& isValid) {
        const uint32_t& first_hash = hash(key, key_len, 0);
        const int64_t& d = _g_table[first_hash % _lookup_len];

        auto& item = d < 0 ? _values[-d-1] : _values[hash(key, key_len, d) % _key_set_len];
        
        isValid = strcmp(key, item->_key) == 0;
            
        return &item->_value;
    }
};

#define PERFECT_HASH_TABLE_LEN 4
enum perfect_hash_table_type {
    HTTP_REQUEST_FP = 0,
    HTTP_RESPONSE_FP = 1,
    HTTP_REQEUST_HEADERS = 2,
    HTTP_RESPONSE_HEADERS = 3
};

struct perfect_hash_visitor {

    perfect_hash<bool> _ph_http_request_fp;
    perfect_hash<bool> _ph_http_response_fp;
    perfect_hash<const char*> _ph_http_request_headers;
    perfect_hash<const char*> _ph_http_response_headers;

    void init_perfect_hash_table_bool(perfect_hash_table_type type, std::vector<perfect_hash_entry<bool>> data) {
        switch(type) {
            case perfect_hash_table_type::HTTP_REQUEST_FP:
                _ph_http_request_fp.create_perfect_hash_table(data, 100);
                break;
            case perfect_hash_table_type::HTTP_RESPONSE_FP:
                _ph_http_response_fp.create_perfect_hash_table(data, 100);
                break;
            case perfect_hash_table_type::HTTP_REQEUST_HEADERS:
            case perfect_hash_table_type::HTTP_RESPONSE_HEADERS:
            default:
                break;
        }
    }

    void init_perfect_hash_table_string(perfect_hash_table_type type, std::vector<perfect_hash_entry<const char*>> data) {
        switch(type) {
            case perfect_hash_table_type::HTTP_REQEUST_HEADERS:
                _ph_http_request_headers.create_perfect_hash_table(data, 100);
                break;
            case perfect_hash_table_type::HTTP_RESPONSE_HEADERS:
                _ph_http_response_headers.create_perfect_hash_table(data, 100);
                break;
            case perfect_hash_table_type::HTTP_REQUEST_FP:
            case perfect_hash_table_type::HTTP_RESPONSE_FP:
                break;
        }
    }

    const char** lookup_string(perfect_hash_table_type type, const char* key, bool& success) {
        switch(type) {
            case perfect_hash_table_type::HTTP_REQEUST_HEADERS:
                return _ph_http_request_headers.lookup(key, strlen(key), success);
            case perfect_hash_table_type::HTTP_RESPONSE_HEADERS:
                return _ph_http_response_headers.lookup(key, strlen(key), success);
            case perfect_hash_table_type::HTTP_REQUEST_FP:
            case perfect_hash_table_type::HTTP_RESPONSE_FP:
            default:
                success = false;
                return nullptr;
        }
    }

    bool* lookup_bool(perfect_hash_table_type type, const char* key, bool& success) {
        switch(type) {
            case perfect_hash_table_type::HTTP_REQUEST_FP:
                return _ph_http_request_fp.lookup(key, strlen(key), success);
            case perfect_hash_table_type::HTTP_RESPONSE_FP:
                return _ph_http_response_fp.lookup(key, strlen(key), success);
            case perfect_hash_table_type::HTTP_REQEUST_HEADERS:
            case perfect_hash_table_type::HTTP_RESPONSE_HEADERS:
            default:
                success = false;
                return nullptr;
        }
    }

    static perfect_hash_visitor& get_default_perfect_hash_visitor() {
        static perfect_hash_visitor ph_visitor;
        return ph_visitor;
    }

    private:
    perfect_hash_visitor() {
        std::vector<perfect_hash_entry<bool>> fp_data_reqeust = {
            { "accept: ", 8, true },
            { "accept-encoding: ", 17, true },
            { "connection: ", 12, true },
            { "dnt: ", 5, true },
            { "dpr: ", 5, true },
            { "upgrade-insecure-requests: ", 27, true },
            { "x-requested-with: ", 18, true },
            { "accept-charset: ", 16, false },
            { "accept-language: ", 17, false },
            { "authorization: ", 15, false },
            { "cache-control: ", 15, false },
            { "host: ", 6, false },
            { "if-modified-since: ", 19, false },
            { "keep-alive: ", 12, false },
            { "user-agent: ", 12, false },
            { "x-flash-version: ", 17, false },
            { "x-p2p-peerdist: ", 16, false } 
        };

        std::vector<perfect_hash_entry<bool>> fp_data_response = {
            { "access-control-allow-credentials: ", 34, true },
            { "access-control-allow-headers: ", 30, true },
            { "access-control-allow-methods: ", 30, true },
            { "access-control-expose-headers: ", 31, true },
            { "cache-control: ", 15, true },
            { "code: ", 6, true },
            { "connection: ", 12, true },
            { "content-language: ", 18, true },
            { "content-transfer-encoding: ", 27, true },
            { "p3p: ", 5, true },
            { "pragma: ", 8, true },
            { "reason: ", 8, true },
            { "server: ", 8, true },
            { "strict-transport-security: ", 27, true },
            { "version: ", 9, true },
            { "x-aspnetmvc-version: ", 21, true },
            { "x-aspnet-version: ", 18, true },
            { "x-cid: ", 7, true },
            { "x-ms-version: ", 14, true },
            { "x-xss-protection: ", 18, true },
            { "appex-activity-id: ", 20, false },
            { "cdnuuid: ", 9, false },
            { "cf-ray: ", 8, false },
            { "content-range: ", 15, false },
            { "content-type: ", 14, false },
            { "date: ", 6, false },
            { "etag: ", 6, false },
            { "expires: ", 9, false },
            { "flow_context: ", 14, false },
            { "ms-cv: ", 7, false },
            { "msregion: ", 10, false },
            { "ms-requestid: ", 14, false },
            { "request-id: ", 12, false },
            { "vary: ", 6, false },
            { "x-amz-cf-pop: ", 14, false },
            { "x-amz-request-id: ", 18, false },
            { "x-azure-ref-originshield: ", 26, false },
            { "x-cache: ", 9, false },
            { "x-cache-hits: ", 14, false },
            { "x-ccc: ", 7, false },
            { "x-diagnostic-s: ", 16, false },
            { "x-feserver: ", 12, false },
            { "x-hw: ", 6, false },
            { "x-msedge-ref: ", 14, false },
            { "x-ocsp-responder-id: ", 21, false },
            { "x-requestid: ", 13, false },
            { "x-served-by: ", 13, false },
            { "x-timer: ", 9, false },
            { "x-trace-context: ", 17, false }
        };

        std::vector<perfect_hash_entry<const char*>> header_data_request = {
            { "user-agent: ", 12, "user_agent" },
            { "host: ", 6, "host"},
            { "x-forwarded-for: ", 17, "x_forwarded_for"},
            { "via: ", 5, "via"},
            { "upgrade: ", 9, "upgrade"},
            { "referer: ", 9, "referer"}
        };

        std::vector<perfect_hash_entry<const char*>> header_data_response = {
            { "content-type: ", 14, "content_type"},
            { "content-length: ", 16, "content_length"},
            { "server: ", 9, "server"},
            { "via: ", 5, "via"}
        };
        
        init_perfect_hash_table_bool(perfect_hash_table_type::HTTP_REQUEST_FP, fp_data_reqeust);
        init_perfect_hash_table_bool(perfect_hash_table_type::HTTP_RESPONSE_FP, fp_data_response);
        init_perfect_hash_table_string(perfect_hash_table_type::HTTP_REQEUST_HEADERS, header_data_request);
        init_perfect_hash_table_string(perfect_hash_table_type::HTTP_RESPONSE_HEADERS, header_data_response);
    }
};

#endif