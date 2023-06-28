/*
 * general_info_test.cc
 *
 * 
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "libmerc_driver_helper.hpp"

TEST_CASE("version_number")
{
    uint8_t v = mercury_get_version_number();
    CHECK(v == 0);
}

TEST_CASE("mercury_get_license_string")
{
    int is_equal = strcmp(mercury_get_license_string(),
                          "Copyright (c) 2019-2020 Cisco Systems, Inc.\n"
                          "All rights reserved.\n"
                          "\n"
                          "  Redistribution and use in source and binary forms, with or without\n"
                          "  modification, are permitted provided that the following conditions\n"
                          "  are met:\n"
                          "\n"
                          "    Redistributions of source code must retain the above copyright\n"
                          "    notice, this list of conditions and the following disclaimer.\n"
                          "\n"
                          "    Redistributions in binary form must reproduce the above\n"
                          "    copyright notice, this list of conditions and the following\n"
                          "    disclaimer in the documentation and/or other materials provided\n"
                          "    with the distribution.\n"
                          "\n"
                          "    Neither the name of the Cisco Systems, Inc. nor the names of its\n"
                          "    contributors may be used to endorse or promote products derived\n"
                          "    from this software without specific prior written permission.\n"
                          "\n"
                          "  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
                          "  \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
                          "  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS\n"
                          "  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE\n"
                          "  COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,\n"
                          "  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\n"
                          "  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n"
                          "  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n"
                          "  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\n"
                          "  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
                          "  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\n"
                          "  OF THE POSSIBILITY OF SUCH DAMAGE.\n"
                          "\n"
                          "For current and comprehensive license information, please see:\n"
                          "\n"
                          " * https://github.com/cisco/mercury/LICENSE for the main license\n"
                          " * https://github.com/cisco/mercury/src/lctrie for the lctrie license;\n"
                          "   this package is copyright 2016-2017 Charles Stewart\n"
                          "   <chuckination_at_gmail_dot_com>\n"
                          " * https://github.com/cisco/mercury/src/rapidjson for the rapidjson license;\n"
                          "   this package is copyright 2015 THL A29 Limited, a Tencent company, and\n"
                          "   Milo Yip.");

    REQUIRE(is_equal == 0);
}

std::string get_version_from_archive(std::string n_archive)
{
    std::string recourse_version{};
    encrypted_compressed_archive archive{n_archive.c_str(), NULL};
    const class archive_node *entry = archive.get_next_entry();
    while (entry != nullptr)
    {
        if (entry->is_regular_file())
        {
            std::string line_str;

            std::string name = entry->get_name();
            if (name == "VERSION")
            {
                while (archive.getline(line_str))
                {
                    recourse_version += line_str;
                }
                break;
            }
        }
    }
    return recourse_version;
}

SCENARIO("test_mercury_get_resource_version")
{
    GIVEN("mercury config")
    {
        libmerc_config config = create_config();

        WHEN("mecrury initialized")
        {
            mercury_context mc = initialize_mercury(config);

            THEN("valid resource version")
            {
                auto version = mercury_get_resource_version(mc);
                auto version_checker = get_version_from_archive(default_resources_path);

                REQUIRE(strcmp(version, version_checker.c_str()) == 0);
            }
            mercury_finalize(mc);
        }
        WHEN("mercury is nullptr")
        {
            mercury_context mc = nullptr;
            THEN("return 0")
            {
                REQUIRE_FALSE(mercury_get_resource_version(mc));
            }
        }
    }
}
