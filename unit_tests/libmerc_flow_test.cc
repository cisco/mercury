/*
 * libmerc_flow_test.cc
 *
 * libmerc unit tests
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "libmerc_driver_helper.hpp"

int test_libmerc(const struct libmerc_config *config, int verbosity, bool fail=false) {
    int num_loops = 4;
    constexpr int num_threads = 8;

    for (int i = 0; i < num_loops; i++) {
        fprintf(stderr, "loop: %d\n", i);

        // bind libmerc
        libmerc_api mercury(path_to_libmerc_library);

        // init mercury
        mercury_context mc = mercury.init(config, verbosity);
        if (mc == NULL) {
            fprintf(stderr, "error: mercury_init() returned null\n");
            return -1;
        }

        // create packet processing threads
        std::array<pthread_t, num_threads> tid_array;
        packet_processor_state thread_state[num_threads] = {
             { 0, &mercury, mc },
             { 1, &mercury, mc },
             { 2, &mercury, mc },
             { 3, &mercury, mc },
             { 4, &mercury, mc },
             { 5, &mercury, mc },
             { 6, &mercury, mc },
             { 7, &mercury, mc }
            };
        //std::array<unsigned int, num_threads> thread_number = { 0, 1, 2, 3, 4, 5, 6, 7 };
        for (int idx=0; idx < num_threads; idx++) {
            pthread_create(&tid_array[idx], NULL, packet_processor, &thread_state[idx]);
        }
        fprintf(stderr, "created all %zu threads\n", tid_array.size());

        if (fail) {
            // delete mercury state, to force failure
            mercury.finalize(mc);
        }

        for (auto & t : tid_array) {
            pthread_join(t, NULL);
        }
        fprintf(stderr, "joined all %zu threads\n", tid_array.size());

        // write stats file
        mercury.write_stats_data(mc, "libmerc_driver_stats.json.gz");

        // destroy mercury
        mercury.finalize(mc);

        fprintf(stderr, "completed mercury_finalize()\n");

        // mercury is unbound from its shared object file when it leaves scope

    }

    return 0;
}

TEST_CASE("bind_test") {
    // initialize libmerc's global configuration by creating a
    // libmerc_config structure and then passing it into mercury_init
    libmerc_config config = create_config();

    libmerc_config config_lite = create_config(); // note: just different, not really lite

    int retval = test_libmerc(&config, verbosity);
    REQUIRE_FALSE(retval);

    retval = test_libmerc(&config_lite, verbosity);
    REQUIRE_FALSE(retval);

    // repeat test with original config
    retval = test_libmerc(&config, verbosity);
    REQUIRE_FALSE(retval);
}


int double_bind_test(const struct libmerc_config *config, const struct libmerc_config *config2) {
    int verbosity = 1;
    int num_loops = 4;
    constexpr int num_threads = 8;

    fprintf(stderr, "running mercury_double_bind() test\n");

    for (int i = 0; i < num_loops; i++) {
        fprintf(stderr, "loop: %d\n", i);

        // bind libmerc
        libmerc_api mercury(path_to_libmerc_library);

        // init mercury
        mercury_context mc = mercury.init(config, verbosity);
        if (mc == nullptr) {
            fprintf(stderr, "error: mercury_init() returned null\n");
            return -1;
        }

        // bind and init second mercury library
        struct libmerc_api mercury_alt(path_to_libmerc_alt_library);
        mercury_context mc_alt = mercury_alt.init(config2, verbosity);
        if (mc_alt == nullptr) {
            fprintf(stderr, "error: mercury_init() returned null in second init\n");
            mercury.finalize(mc);
            return -1;
        }

        // create packet processing threads
        std::array<pthread_t, num_threads> tid_array;
        packet_processor_state thread_state[num_threads] = {
             { 0, &mercury, mc },
             { 1, &mercury, mc },
             { 2, &mercury, mc },
             { 3, &mercury, mc },
             { 4, &mercury_alt, mc_alt },
             { 5, &mercury_alt, mc_alt },
             { 6, &mercury_alt, mc_alt },
             { 7, &mercury_alt, mc_alt }
            };
        for (int idx=0; idx < num_threads; idx++) {
            pthread_create(&tid_array[idx], NULL, packet_processor, &thread_state[idx]);
        }
        fprintf(stderr, "created all %zu threads\n", tid_array.size());

        mercury.write_stats_data(mc, "libmerc_driver_stats_pre_join.json.gz");
        mercury.write_stats_data(mc_alt, "libmerc_driver_stats_pre_join_alt.json.gz");

        for (auto & t : tid_array) {
            pthread_join(t, NULL);
        }
        fprintf(stderr, "joined all %zu threads\n", tid_array.size());

        // write stats file
        mercury.write_stats_data(mc, "libmerc_driver_stats_post_join.json.gz");
        mercury.write_stats_data(mc_alt, "libmerc_driver_stats_post_join_alt.json.gz");

        // destroy mercury
        mercury.finalize(mc);

        fprintf(stderr, "completed mercury_finalize()\n");

        // mercury and mercury_alt are unbound from its shared object
        // file when they leave scope

        mercury_alt.finalize(mc_alt);

    }

    return 0;
}

TEST_CASE("double_bind_test") {  
    libmerc_config config = create_config();
    libmerc_config config_lite = create_config(); // note: just different, not really lite

    // perform double bind/init test
    int retval = double_bind_test(&config_lite, &config);
    REQUIRE_FALSE(retval);
}
