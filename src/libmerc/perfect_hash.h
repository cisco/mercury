#ifndef PERFECT_HASH_H
#define PERFECT_HASH_H

#include <string>
#include <cstring>
#include <vector>
#include <algorithm>

template<typename T>
struct perfect_hash_entry
{
    public:
    perfect_hash_entry(const char* key, size_t key_len, T value)
    {
        _value = value;
        _key = key;
        _key_len = key_len;
    }

    size_t _key_len = -1;
    const char* _key = nullptr;
    uint32_t _hash = 0;

    union { T _value;};
};

template<typename T>
struct perfect_hash
{
    private:
    std::vector<std::vector<perfect_hash_entry<T>>> _buckets;

    long* _g_table;
    perfect_hash_entry<T>** _values;

    size_t _key_set_len;
    size_t _lookup_len;

    public:
    void cleanup()
    {
        _buckets.clear();
        delete[] _g_table;
        for(size_t i = 0; i < _key_set_len; i++)
        {
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

    inline uint32_t rotl32 ( uint32_t x, int8_t r )
    {
        return (x << r) | (x >> (32 - r));
    }

    inline uint32_t fmix32 ( uint32_t h )
    {
      h ^= h >> 16;
      h *= 0x85ebca6b;
      h ^= h >> 13;
      h *= 0xc2b2ae35;
      h ^= h >> 16;

      return h;
    }

    //Murmur2
    inline uint32_t hash(const char* key, size_t len, const uint32_t& res)
    {
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
  case 2: h ^= data[1] << 8;
  case 1: h ^= data[0];
      h *= m;
  };

  /* Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.  */

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
        // uint32_t h = res;
        // uint32_t k;
        // /* Read in groups of 4. */
        // for (size_t i = len >> 2; i; --i) {
        //     // Here is a source of differing results across endiannesses.
        //     // A swap here has no effects on hash properties though.
        //     memcpy(&k, key, sizeof(uint32_t));
        //     key += sizeof(uint32_t);
        //     h ^= murmur_32_scramble(k);
        //     h = (h << 13) | (h >> 19);
        //     h = h * 5 + 0xe6546b64;
        // }
        // /* Read the rest. */
        // k = 0;
        // for (size_t i = len & 3; i; --i) {
        //     k <<= 8;
        //     k |= key[i - 1];
        // }
        // // A swap is *not* necessary here because the preceding loop already
        // // places the low bytes in the low places according to whatever endianness
        // // we use. Swaps only apply when the memory is copied in a chunk.
        // h ^= murmur_32_scramble(k);
        // /* Finalize. */
	    // h ^= len;
	    // h ^= h >> 16;
	    // h *= 0x85ebca6b;
	    // h ^= h >> 13;
	    // h *= 0xc2b2ae35;
	    // h ^= h >> 16;
	    // return h;
    }

    bool contains_value(size_t* arr, size_t len, size_t val)
    {
        for(size_t i = 0; i < len; i++)
        {
            if(arr[i] == val)
                return true;
        }
        return false;
    }

    size_t next_pow2(size_t s)
    {
        size_t res = 1;
        while(s > res)
        {
            res *= 2;
        }
        return res;
    }

    size_t hash_to_indx(uint32_t hash, size_t size)
    {
        return hash & (size-1);
    }

    void create_perfect_hash_table(std::vector<perfect_hash_entry<T>>& data_set, size_t load_factor)
    {
        _key_set_len = data_set.size();

        _key_set_len = next_pow2(_key_set_len);

        _lookup_len = (load_factor * _key_set_len) / 100;

        _values = new perfect_hash_entry<T>*[_key_set_len];

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
            auto tmp_indx = hash_to_indx(hash(data._key, data._key_len, 0), _lookup_len);
            _buckets.at(tmp_indx).push_back(data);
        }
        
        std::sort(_buckets.begin(), _buckets.end(), [](const std::vector<perfect_hash_entry<T>>& rv, const std::vector<perfect_hash_entry<T>>& lv)
        {
            return rv.size() > lv.size();
        });
        
        _g_table = new long[_lookup_len];

        size_t* pslots = nullptr;

        for(size_t indx = 0; indx < _lookup_len; indx++)
        {
            if(_buckets[indx].size() <= 1) break;

            auto bucket = _buckets[indx];

            size_t d, item;
            d = 1;
            item = 0;

            if(pslots == nullptr)
                pslots = new size_t[bucket.size()];

            std::fill_n(pslots, bucket.size(), -1);
            
            while(item < bucket.size())
            {
                size_t slot = hash_to_indx(hash(bucket.at(item)._key, bucket.at(item)._key_len, d), _key_set_len);
                if(_values[slot] != nullptr || contains_value(pslots, item, slot))
                {
                    d += 1;
                    if(d < 0) break;
                    item = 0;
                    
                    std::fill_n(pslots, bucket.size(), -1);
                }
                else
                {
                    pslots[item] = slot;
                    item += 1;
                }
            }
            if(d < 0)
            {
                exit(1);
            }
            
            _g_table[hash(bucket[0]._key, bucket[0]._key_len, 0) % _lookup_len] = d;
            for(size_t c = 0; c < bucket.size(); c++)
            {
                _values[pslots[c]] = new perfect_hash_entry<T>(bucket[c]);
                _values[pslots[c]]->_hash = hash(bucket[c]._key, bucket[c]._key_len, 0);
            }
        }
        delete[] pslots;


        std::vector<long> free_list;
        for(size_t i = 0; i < _key_set_len; i++)
        {
            if(_values[i] == nullptr)
                free_list.push_back(i);
        }
                
        for(size_t b = 0; b < _lookup_len; b++)
        {
            auto bucket = _buckets[b];
            if(bucket.size() == 0 || bucket.size() > 1) continue;
            auto slot = free_list.back();
            free_list.pop_back();
            _g_table[hash_to_indx(hash(bucket[0]._key, bucket[0]._key_len, 0), _lookup_len)] = -slot-1;
            _values[slot] = new perfect_hash_entry<T>(bucket[0]);
            _values[slot]->_hash = hash(bucket[0]._key, bucket[0]._key_len, 0);
        }
    }

    inline T* lookup(const char* key, const size_t& key_len, bool& isValid)
    {
        const uint32_t& first_hash = hash(key, key_len, 0);
        const long& d = _g_table[first_hash % _lookup_len];

        auto& item = d < 0 ? _values[-d-1] : _values[hash_to_indx(hash(key, key_len, d), _key_set_len)];
        
        isValid = first_hash == item->_hash;
            
        return &item->_value;
    }
};

#define PERFECT_HASH_TABLE_LEN 4
enum perfect_hash_table_type 
{
    HTTP_REQUEST_FP = 0,
    HTTP_RESPONSE_FP = 1,
    HTTP_REQEUST_HEADERS = 2,
    HTTP_RESPONSE_HEADERS = 3
};

struct perfect_hash_visitor
{
    perfect_hash<bool> _ph_http_request_fp;
    perfect_hash<bool> _ph_http_response_fp;
    perfect_hash<const char*> _ph_http_request_headers;
    perfect_hash<const char*> _ph_http_response_headers;

    void init_perfect_hash_table_bool(perfect_hash_table_type type, std::vector<perfect_hash_entry<bool>> data)
    {
        switch(type)
        {
            case perfect_hash_table_type::HTTP_REQUEST_FP:
                _ph_http_request_fp.create_perfect_hash_table(data, 100);
            break;
            case perfect_hash_table_type::HTTP_RESPONSE_FP:
                _ph_http_response_fp.create_perfect_hash_table(data, 100);
            break;
        }
    }

    void init_perfect_hash_table_string(perfect_hash_table_type type, std::vector<perfect_hash_entry<const char*>> data)
    {
        switch(type)
        {
            case perfect_hash_table_type::HTTP_REQEUST_HEADERS:
                _ph_http_request_headers.create_perfect_hash_table(data, 100);
            break;
            case perfect_hash_table_type::HTTP_RESPONSE_HEADERS:
                _ph_http_response_headers.create_perfect_hash_table(data, 100);
            break;
        }
    }

    const char** lookup_string(perfect_hash_table_type type, const char* key, bool& success)
    {
        switch(type)
        {
            case perfect_hash_table_type::HTTP_REQEUST_HEADERS:
                return _ph_http_request_headers.lookup(key, strlen(key), success);
            case perfect_hash_table_type::HTTP_RESPONSE_HEADERS:
                return _ph_http_response_headers.lookup(key, strlen(key), success);
            default:
                return nullptr;
        }
    }

    bool* lookup_bool(perfect_hash_table_type type, const char* key, bool& success)
    {
        switch(type)
        {
            case perfect_hash_table_type::HTTP_REQUEST_FP:
                return _ph_http_request_fp.lookup(key, strlen(key), success);
            case perfect_hash_table_type::HTTP_RESPONSE_FP:
                return _ph_http_response_fp.lookup(key, strlen(key), success);
            default:
                return nullptr;
        }
    }
};

#endif