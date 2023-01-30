// perfect_hash.h
//
// Copyright (c) 2023 Cisco Systems, Inc. All rights reserved.  License at
// https://github.com/cisco/mercury/blob/master/LICENSE

#ifndef PERFECT_HASH_H
#define PERFECT_HASH_H

//Hash, displace, and compress algorithm was taken as reference
//https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.568.130&rep=rep1&type=pdf

#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <optional>

template<typename T>
struct perfect_hash_entry
{
public:
    perfect_hash_entry(const char* key, size_t key_len, T value) {
        _value = value;
        _key = key;
        _key_len = key_len;
    }

    perfect_hash_entry(const char* key,     // must be null-terminated
                       T value)
    {
        _value = value;
        _key = key;
        _key_len = strlen(key);
    }

    size_t _key_len = -1;
    const char* _key = nullptr;
    uint32_t _hash = 0;

    T _value;
};

/*
 * MurmurHash By Austin Appleby https://sites.google.com/site/murmurhash/
 * The original implementation is modified slightly to make the computation
 * case insensitive. This is done by the below masking trick.
 * 'A' | 0x20 = 'a';
 * This trick works as long as the input is Alphabets, space, semicolon.
 * Since the keys that are currently used is combination of alphabatets,
 * space and semicolon, this works. If the keys needs to have other
 * ascii characters, then probably functions like tolower() needs to be used.
 */
struct murmur2_hash {

    uint32_t operator() (const char* key, size_t len, const uint32_t& res) {
        /* 'm' and 'r' are mixing constants generated offline.
           They're not really 'magic', they just happen to work well.  */

        static constexpr uint32_t m = 0x5bd1e995;
        static constexpr int r = 24;

        /* Initialize the hash to a 'random' value */

        uint32_t h = res ^ len;

        /* Mix 4 bytes at a time into the hash */

        const unsigned char * data = (const unsigned char *)key;

        while(len >= 4) {
            uint32_t k = *(uint32_t*)data | 0x20202020; //for case-insensitive comparision

            k *= m;
            k ^= k >> r;
            k *= m;

            h *= m;
            h ^= k;

            data += 4;
            len -= 4;
        }

        /* Handle the last few bytes of the input array  */

        switch(len) {
        case 3: h ^= (data[2] | 0x20) << 16;
            [[fallthrough]];
        case 2: h ^= (data[1] | 0x20) << 8;
            [[fallthrough]];
        case 1: h ^= (data[0] | 0x20);
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

    enum load_factor : size_t {
        FASTEST_GENERATION_TIME = 100,      // requires 8 * N bytes additional memory allocation, provides fastest lookup table genaration
        SMALLEST_LOOKUP_TABLE_SIZE = 20,    // requires 8 * (N/5) bytes additional memory allocation, provides smallest lookup table size
        DEFAULT = FASTEST_GENERATION_TIME
    };

private:
    int64_t* _g_table = nullptr;
    perfect_hash_entry<T>** _values = nullptr;

    size_t _key_set_len;
    size_t _lookup_len;

    murmur2_hash hash;

    void create_perfect_hash_table(std::vector<perfect_hash_entry<T>>& data_set, size_t load_factor) {
        _key_set_len = data_set.size();

        _lookup_len = (load_factor * _key_set_len) / 100;

        _values = new perfect_hash_entry<T>*[_key_set_len];

        std::vector<std::vector<perfect_hash_entry<T>>> _buckets;

        for(size_t i = 0; i < _key_set_len; i++) {
            _values[i] = nullptr;
        }

        for(size_t i = 0; i < _lookup_len; i++) {
            _buckets.push_back({});
        }

        for(const auto& data : data_set) {
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
                    if(d == UINT32_MAX) break;
                    item = 0;

                    std::fill_n(pslots, bucket.size(), -1);
                }
                else {
                    pslots[item] = slot;
                    item += 1;
                }
            }
            if(d == UINT32_MAX) {
                throw std::runtime_error("could not create perfect hash function");
            }

            _g_table[hash(bucket[0]._key, bucket[0]._key_len, 0) % _lookup_len] = static_cast<int64_t>(d);
            for(size_t c = 0; c < bucket.size(); c++) {
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

    bool contains_value(int64_t* arr, size_t len, int64_t val) {
        for(size_t i = 0; i < len; i++) {
            if(arr[i] == val)
                return true;
        }
        return false;
    }

public:

    perfect_hash(std::vector<perfect_hash_entry<T>>& data_set, size_t load_factor=DEFAULT) {
        create_perfect_hash_table(data_set, load_factor);
    }

    perfect_hash(std::vector<std::pair<std::string, T>> data, size_t load_factor=DEFAULT) {
        std::vector<perfect_hash_entry<T>> tmp_data;
        for(size_t i = 0; i < data.size(); i++) {
            tmp_data.push_back({strdup(data[i].first.c_str()), data[i].first.length(), data[i].second});
        }
        create_perfect_hash_table(tmp_data, load_factor);
    }

    ~perfect_hash() {
        if(_g_table && _values) {
            delete[] _g_table;
            for(size_t i = 0; i < _key_set_len; i++){
                delete _values[i];
            }
            delete[] _values;
        }
    }

    inline T* lookup(const uint8_t* k, const size_t key_len, bool& isValid) {
        const char *key = (const char *)k;
        const uint32_t& first_hash = hash(key, key_len, 0);
        const int64_t& d = _g_table[first_hash % _lookup_len];

        auto& item = d < 0 ? _values[-d-1] : _values[hash(key, key_len, d) % _key_set_len];

        isValid = item->_key_len == key_len && strncasecmp(key, item->_key, key_len) == 0;

        return &item->_value;
    }

    std::optional<T> lookup(const uint8_t* k, const size_t key_len) {
        const char *key = (const char *)k;
        const uint32_t& first_hash = hash(key, key_len, 0);
        const int64_t& d = _g_table[first_hash % _lookup_len];

        perfect_hash_entry<T> *item = d < 0 ? _values[-d-1] : _values[hash(key, key_len, d) % _key_set_len];

        bool isValid = item->_key_len == key_len && strncasecmp(key, item->_key, key_len) == 0;

        if (isValid) {
            return item->_value;
        }
        return std::nullopt;
    }
};

#endif
