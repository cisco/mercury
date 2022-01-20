/*
 * libmerc_driver.cc
 *
 * main() file for libmerc.so test driver program
 *
 * Copyright (c) 2020-2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "libmerc_driver_helper.hpp"

//TODO: make a scenario
TEST_CASE("check_global_vars_configuration") {
    libmerc_config config = create_config();
    
    // init mercury
    mercury_context mc = initialize_mercury(config);
    REQUIRE(mc != nullptr);

    check_global_configuraton(mc, config);


}

SCENARIO("test_mercury_init") {
    GIVEN("mecrury config") {
        libmerc_config config = create_config();
    
        WHEN("After initialize") {
            THEN("merciry initialized ") {
                mercury_context mc = initialize_mercury(config);
                REQUIRE(mc != nullptr);
            }
        }

        // WHEN("Set resources to nullptr") { /*failed: mercury context created in this case*/
        //     config.resources = nullptr;
        //     THEN("Cannot initialize mercury context: return nullptr") {
        //         REQUIRE(mercury_init(&config, verbosity) == nullptr);
        //     }
        // }

        WHEN("Set resources to empty") {
            config.resources = (char *) "";
            THEN("Cannot initialize mercury context: return nullptr") {
                REQUIRE(mercury_init(&config, verbosity) == nullptr);
            }
        }
    }
}

SCENARIO("test_mercury_finalize") {
    GIVEN("mecrury context") {
        libmerc_config config = create_config();
    
        // init mercury
        mercury_context mc = initialize_mercury(config);

        WHEN("After initialize") {
            THEN("merciry initialized ") {
                REQUIRE(mc != nullptr);
            }
        }

        WHEN("Finish") {
            THEN("Correct finilize: return 0") {
                REQUIRE(mercury_finalize(mc) == 0);
            }
        }

        // WHEN("Finish two times") { /*failed: facing exception instead of -1, because mc deleted but pointer not nullptr*/
        //     THEN("Incorrect behaviour: return -1") {
        //         REQUIRE(mercury_finalize(mc) == 0);
        //         CHECK(mc == nullptr);
        //         //CHECK(mc->global_vars.certs_json_output == false); /*exception as memory under pointer already dealocated*/
        //         //CHECK(mercury_finalize(mc) == -1);  /*check in ~mercury() also needed*/
        //     }
        // }
    }  
}

SCENARIO("test_packet_processor_construct") {
    GIVEN("mercury context") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        WHEN("Mercury context is correct") {
            THEN("packet processor created") {
                auto mpp = mercury_packet_processor_construct(mc);
                REQUIRE(mpp != NULL);

                /*avoid memory leaks*/
                mercury_packet_processor_destruct(mpp);
            }
        }

        // WHEN("Mercury context is finalized") { /*failed: no check for mercury_context is nullptr*/
        //      mercury_finalize(mc);
        //      THEN("packet processor set to NULL") {
        //          REQUIRE(mercury_packet_processor_construct(mc) == NULL);
        //      }
        // }

        WHEN("mercury classifier is nullptr") {
            mc->c = nullptr;
            THEN("packet processor set to NULL") {
                auto mpp = mercury_packet_processor_construct(mc);
                REQUIRE(mpp == NULL);
            }
        }

        WHEN("mercury classifier is nullptr and analysis isn`t needed") {
            mc->c = nullptr;
            mc->global_vars.do_analysis = false;
            THEN("packet processor created") {
                auto mpp = mercury_packet_processor_construct(mc);
                REQUIRE(mpp != NULL);

                /*avoid memory leaks*/
                mercury_packet_processor_destruct(mpp);
            }
        }

        //TODO: WHEN("Do_stats and message queue is empty") {}
    }
}

SCENARIO("test_packet_processor_destruct") {
    GIVEN("packet processor") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

        WHEN("destruct packet processor") {
            THEN("no throws catched") {
                REQUIRE_NOTHROW(mercury_packet_processor_destruct(mpp));
            }
        }  

        // WHEN("destruct twice") {
        //     THEN("throws catched") {
        //         REQUIRE_NOTHROW(mercury_packet_processor_destruct(mpp));
        //         REQUIRE_THROWS(mercury_packet_processor_destruct(mpp));
        //     }
        // }

        // WHEN("packet processor is nullptr") { /*failed: no exception. memory leak*/
        //     mpp = nullptr;
        //     THEN("throws catched") {
        //         REQUIRE_THROWS(mercury_packet_processor_destruct(mpp));
        //     }
        // } 
    }
}

SCENARIO("test_write_stats_data") {
    GIVEN("mercury context and stats file") {
        libmerc_config config = create_config();
        config.packet_filter_cfg = (char *)"tls";
        mercury_context mc = initialize_mercury(config);
        char * stats_file = (char *)"merc_stats_0.json.gz";

        WHEN("") {
            THEN("write stats file") {
                REQUIRE(mercury_write_stats_data(mc, stats_file));
            }
        }

        WHEN("mercury context is null") {
            THEN("codn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(nullptr, stats_file));
            }
        }

       /* WHEN("mercury finalized") { //seg fault
            mercury_finalize(mc);
            THEN("couldn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(mc, stats_file));
            }
        }x*/

        WHEN("empty stats file name") {
            THEN("couldn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(mc, ""));
            }
        }

        WHEN("stats file is null") {
            stats_file = nullptr;
            THEN("couldn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(mc, stats_file));
            }
        }
    }
}

SCENARIO("test packet_processor_get_analysis_context") {
    GIVEN("mercury packet processor") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

        struct timespec time;
        time.tv_sec = time.tv_nsec = 0;  // set to January 1st, 1970 (the Epoch)

        WHEN("get analysis context") {
            mercury_packet_processor_get_analysis_context(mpp, nullptr, 0, &time);
            THEN("not a valid result") {
                REQUIRE_FALSE(mpp->analysis.result.is_valid());

                mercury_packet_processor_destruct(mpp);
            }
        }

        WHEN("get analysis context") {
            mercury_packet_processor_get_analysis_context(mpp, client_hello_eth, client_hello_eth_len, &time);
            THEN("a valid result  exist") {
                REQUIRE(mpp->analysis.result.is_valid());
                mercury_packet_processor_destruct(mpp);
            }
        }
    }
}

SCENARIO("test packet_processor_ip_get_analysis_context") {
    GIVEN("mercury packet processor") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

        struct timespec time;
        time.tv_sec = time.tv_nsec = 0;  // set to January 1st, 1970 (the Epoch)

        WHEN("get analysis context") {
            mercury_packet_processor_ip_get_analysis_context(mpp, nullptr, 0, &time);
            THEN("not a valid result") {
                REQUIRE_FALSE(mpp->analysis.result.is_valid());
 
                mercury_packet_processor_destruct(mpp);
            }
        }
    }
}

unsigned char http_get[] = {
  0x02, 0xd6, 0x51, 0xf5, 0x98, 0x92, 0x02, 0xd6, 0x51, 0xf5, 0x98, 0x8b, 0x08, 0x00, 0x45, 0x00,  
  0x00, 0xfa, 0xac, 0x54, 0x00, 0x00, 0x80, 0x06, 0x79, 0x8a, 0x0a, 0x0a, 0x00, 0x0a, 0x0a, 0x0a,  
  0x00, 0x02, 0xcd, 0x73, 0x00, 0x50, 0x12, 0x08, 0xa6, 0x5a, 0x12, 0x08, 0xab, 0x6f, 0x50, 0x18,  
  0x80, 0x00, 0x46, 0x24, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x34, 0x35, 0x30, 0x20, 0x48,  
  0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x31,  
  0x30, 0x2e, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x32, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,  
  0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x55, 0x73, 0x65,  
  0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61,  
  0x2f, 0x34, 0x2e, 0x30, 0x20, 0x28, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x69, 0x62, 0x6c, 0x65,  
  0x3b, 0x20, 0x4d, 0x53, 0x49, 0x45, 0x20, 0x36, 0x2e, 0x30, 0x3b, 0x20, 0x57, 0x69, 0x6e, 0x64,  
  0x6f, 0x77, 0x73, 0x20, 0x4e, 0x54, 0x20, 0x35, 0x2e, 0x31, 0x29, 0x20, 0x4f, 0x70, 0x65, 0x72,  
  0x61, 0x20, 0x38, 0x2e, 0x30, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a,  
  0x2f, 0x2a, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75,  
  0x61, 0x67, 0x65, 0x3a, 0x20, 0x65, 0x6e, 0x2d, 0x75, 0x73, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65,  
  0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69,  
  0x70, 0x2c, 0x20, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x20, 0x63, 0x6f, 0x6d, 0x70,  
  0x72, 0x65, 0x73, 0x73, 0x0d, 0x0a, 0x0d, 0x0a
};

SCENARIO("test single packet http analysis and performance") {
    libmerc_config config = create_config();
    config.do_analysis = true;
    config.metadata_output = true;
    config.packet_filter_cfg = "http";
    mercury_context mc = initialize_mercury(config);
    mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

    struct timespec time;
    time.tv_sec = time.tv_nsec = 0;  // set to January 1st, 1970 (the Epoch)

    const analysis_context* a;

    BENCHMARK("performance")
    {
        for(size_t i = 0; i < 1; i++)
        {
            a = mercury_packet_processor_get_analysis_context(mpp, http_get, 264, &time);
        }
    }

    REQUIRE(a != nullptr);
    REQUIRE(a->result.is_valid());

    mercury_packet_processor_destruct(mpp);
    mercury_finalize(mc);
}

