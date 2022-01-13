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
size_t loop_count_2 = 100000;
size_t key_len_1 = 20;
size_t key_len_2 = 50;

void prepare_data(size_t l, size_t k)
{
    if(_test_data.empty() == false)
        return;

    for(size_t i = 0; i < l; i++)
    {
        _test_data.push_back(gen_random(k));
    }
}

SCENARIO("Perfect Hash. Key len = 20; Elements = 100; Lookup count = 100")
{
    prepare_data(loop_count_1, key_len_1);

    

    std::vector<perfect_hash_entry<int>> test_data;
    
    std::string select = {};

    srand(time(NULL));

    for(size_t i = 0; i < loop_count_1; i++)
    {
        test_data.push_back({strdup(_test_data[i].c_str()), _test_data[i].length(), i});
    }

    perfect_hash<int>* ph = nullptr;

    BENCHMARK("Perfect Hash generation table")
    {
        ph = new perfect_hash<int>(test_data);
    }
    
    std::vector<int*> res;
    res.reserve(loop_count_1);
    bool valid = false;
    BENCHMARK("Perfect Hash lookup")
    {
        for(size_t i = 0; i < loop_count_1; i++)
        {
            res[i] = ph->lookup(_test_data[i].c_str(), _test_data[i].length(), valid);
        }
    }
    valid = false;
    for(int i = 0; i < (int)loop_count_1; i++)
    {
        valid |= *res[i] != i;
        printf("\n\n%d\n\n", *res[i]);
    }
    REQUIRE_FALSE(valid);
    for(auto& d : test_data)
    {
        free((char*)d._key);
        d._key = nullptr;
    }
}

SCENARIO("Unordered Map. Key len = 20; Elements = 100; Lookup count = 1000")
{
    prepare_data(loop_count_1, key_len_1);

    std::unordered_map<std::string, int*> test_data;

    for(size_t i = 0; i < loop_count_1; i++)
    {
        test_data.insert({_test_data[i], new int(i)});
    }
    std::vector<int*> res;
    res.reserve(loop_count_1 * 100);
    BENCHMARK("Unordered Map lookup")
    {
        for(size_t i = 0; i < loop_count_1; i++)
        {
            res[i] = test_data.find(_test_data[i])->second;
        }
    }
    for(auto s : res)
    {
        printf("\n\n%d\n\n", *s);
    }

    for(size_t i = 0; i < loop_count_1; i++)
    {
        delete test_data.find(_test_data[i])->second;
    }
}

SCENARIO("Perfect Hash. Key len = 50; Elements = 100000; Lookup count = 100000")
{
    _test_data.clear();

    prepare_data(loop_count_2, key_len_2);

    std::vector<perfect_hash_entry<int>> test_data;
    
    std::string select = {};

    srand(time(NULL));

    for(size_t i = 0; i < loop_count_2; i++)
    {
        test_data.push_back({strdup(_test_data[i].c_str()), _test_data[i].length(), i});
    }

    perfect_hash<int>* ph = nullptr;

    BENCHMARK("Perfect Hash generation table")
    {
        ph = new perfect_hash<int>(test_data);
    }
    
    std::vector<int*> res;
    res.reserve(loop_count_2);
    bool valid = false;
    BENCHMARK("Perfect Hash lookup")
    {
        for(size_t i = 0; i < loop_count_2; i++)
        {
            res[i] = ph->lookup(_test_data[i].c_str(), _test_data[i].length(), valid);
        }
    }
    valid = false;
    for(size_t i = 0; i < loop_count_2; i++)
    {
        valid |= *res[i] != (int)i;
        printf("%d\n", *res[i]);
    }
    REQUIRE_FALSE(valid);
    for(auto& d : test_data)
    {
        free((char*)d._key);
        d._key = nullptr;
    }
}

SCENARIO("Unordered Map. Key len = 50; Elements = 100000; Lookup count = 100000")
{
    prepare_data(loop_count_2, key_len_2);

    std::unordered_map<std::string, int*> test_data;

    for(size_t i = 0; i < loop_count_2; i++)
    {
        test_data.insert({_test_data[i], new int(i)});
    }
    std::vector<int*> res;
    res.reserve(loop_count_2);
    BENCHMARK("Unordered Map lookup")
    {
        for(size_t i = 0; i < loop_count_2; i++)
        {
            res[i] = test_data.find(_test_data[i])->second;
        }
    }
    for(auto s : res)
    {
        printf("\n\n%d\n\n", *s);
    }

    for(size_t i = 0; i < loop_count_2; i++)
    {
        delete test_data.find(_test_data[i])->second;
    }
}