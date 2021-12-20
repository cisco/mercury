#include <perfect_hash.h>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <unordered_map>

std::string gen_random(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    return tmp_s;
}

static std::vector<std::string> _test_data = {};

size_t loop_count_1 = 100;
size_t key_len = 20;

void prepare_data()
{
    if(_test_data.empty() == false)
        return;

    for(size_t i = 0; i < loop_count_1; i++)
    {
        _test_data.push_back(gen_random(key_len));
    }
}

SCENARIO("Perfect Hash. Key len = 20; Elements = 100; Lookup count = 1000")
{
    prepare_data();

    perfect_hash<int> ph;

    std::vector<perfect_hash_entry<int>> test_data;
    
    std::string select = {};

    srand(time(NULL));

    for(size_t i = 0; i < loop_count_1; i++)
    {
        test_data.push_back({strdup(_test_data[i].c_str()), _test_data[i].length(), i});
    }

    BENCHMARK("Perfect Hash generation table")
    {
        ph.create_perfect_hash_table(test_data, 100);
    }
    
    std::vector<int*> res;
    bool valid = false;
    BENCHMARK("Perfect Hash lookup")
    {
        for(int i = 0; i <  100; i++)
        for(auto s : _test_data)
        {
            res.push_back(ph.lookup(s.c_str(), s.length(), valid));
        }
    }
    for(auto s : res)
    {
        printf("\n\n%d\n\n", *s);
    }
    for(auto& d : test_data)
    {
        free((char*)d._key);
        d._key = nullptr;
    }
    ph.cleanup();
}

SCENARIO("Unordered Map. Key len = 20; Elements = 100; Lookup count = 1000")
{
    prepare_data();

    std::unordered_map<std::string, int*> test_data;

    for(size_t i = 0; i < loop_count_1; i++)
    {
        test_data.insert({_test_data[i], new int(i)});
    }
    std::vector<int*> res;
    BENCHMARK("Unordered Map lookup")
    {
        for(int i = 0; i <  100; i++)
        for(auto s : _test_data)
        {
            res.push_back(test_data.find(s)->second);
        }
    }
    for(auto s : res)
    {
        printf("\n\n%d\n\n", *s);
    }

    test_data.clear();
}

SCENARIO("Perfect Hash. Key len = 50; Elements = 100000; Lookup count = 100000")
{
    loop_count_1 = 100000;
    key_len = 50;

    _test_data.clear();

    prepare_data();

    perfect_hash<int> ph;

    std::vector<perfect_hash_entry<int>> test_data;
    
    std::string select = {};

    srand(time(NULL));

    for(size_t i = 0; i < loop_count_1; i++)
    {
        test_data.push_back({strdup(_test_data[i].c_str()), _test_data[i].length(), i});
    }

    BENCHMARK("Perfect Hash generation table")
    {
        ph.create_perfect_hash_table(test_data, 100);
    }
    
    std::vector<int*> res;
    bool valid = false;
    BENCHMARK("Perfect Hash lookup")
    {
        for(auto s : _test_data)
        {
            res.push_back(ph.lookup(s.c_str(), s.length(), valid));
        }
    }
    for(auto s : res)
    {
        printf("\n\n%d\n\n", *s);
    }
    for(auto& d : test_data)
    {
        free((char*)d._key);
        d._key = nullptr;
    }
    ph.cleanup();
}

SCENARIO("Unordered Map. Key len = 50; Elements = 100000; Lookup count = 100000")
{
    prepare_data();

    std::unordered_map<std::string, int*> test_data;

    for(size_t i = 0; i < loop_count_1; i++)
    {
        test_data.insert({_test_data[i], new int(i)});
    }
    std::vector<int*> res;
    BENCHMARK("Unordered Map lookup")
    {
        for(auto s : _test_data)
        {
            res.push_back(test_data.find(s)->second);
        }
    }
    for(auto s : res)
    {
        printf("\n\n%d\n\n", *s);
    }

    test_data.clear();
}