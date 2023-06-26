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
    mercury_finalize(mc);

}

SCENARIO("test_mercury_init") {
    GIVEN("mecrury config") {
        libmerc_config config = create_config();
    
        WHEN("After initialize") {
            THEN("merciry initialized ") {
                mercury_context mc = initialize_mercury(config);
                REQUIRE(mc != nullptr);
                mercury_finalize(mc);
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

        int ret = mercury_finalize(mc);

        WHEN("Finish") {
            THEN("Correct finilize: return 0") {
                REQUIRE(ret == 0);
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
        
        /*memory leaks*/
        // WHEN("mercury classifier is nullptr") {
        //     mc->c = nullptr;
        //     THEN("packet processor set to NULL") {
        //         auto mpp = mercury_packet_processor_construct(mc);
        //         REQUIRE(mpp == NULL);
        //     }
        // }
        // WHEN("mercury classifier is nullptr and analysis isn`t needed") {
        //     mc->c = nullptr;
        //     mc->global_vars.do_analysis = false;
        //     THEN("packet processor created") {
        //         auto mpp = mercury_packet_processor_construct(mc);
        //         REQUIRE(mpp != NULL);

        //         /*avoid memory leaks*/
        //         mercury_packet_processor_destruct(mpp);
        //     }
        // }

        //TODO: WHEN("Do_stats and message queue is empty") {}
        mercury_finalize(mc);
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
        mercury_finalize(mc);
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
        mercury_finalize(mc);
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
        mercury_finalize(mc);
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
        mercury_finalize(mc);
    }
}
