/*
 * python_interface.c
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include <pthread.h>
#include "python_interface.h"
#include "python-inference/tls_fingerprint_min_api.h"

pthread_mutex_t lock_fp_cache;
std::unordered_map<std::string,char*> fp_cache;

PyThreadState *main_thread_state = NULL;

int init_python() {
    // check to see if python is already initialized
    if (main_thread_state != NULL) {
        return -1;
    }
  
    if (pthread_mutex_init(&lock_fp_cache, NULL) != 0) { 
        printf("\n mutex init has failed\n"); 
        return -1; 
    }
    fp_cache = {};

    Py_Initialize();
    PyEval_InitThreads();
    PyRun_SimpleString("import sys");
    char buf[128];
    char buf2[256];
    memset(buf, 0, sizeof(buf));
    memset(buf2, 0, sizeof(buf2));
    ssize_t num_bytes_read = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (num_bytes_read == -1) {
        perror("readlink failed");
        return -1; /* error */
    }
    int i;
    for (i = 127; i >= 0; i--) {
        if (buf[i] == '/') {
            break;
        } else {
            buf[i] = '\0';
        }
    }
    sprintf(buf2, "sys.path.append(\"%s\")", buf);
    PyRun_SimpleString(buf2);
    if (PyErr_Occurred()) {
        PyErr_Print();
        return -1;
    }

    import_tls_fingerprint_min();
    if (PyErr_Occurred()) {
        PyErr_Print();
        return -1;
    }

    main_thread_state = PyThreadState_Get();

    PyEval_SaveThread();
    if (PyErr_Occurred()) {
        PyErr_Print();
        return -1;
    }

    return 0;
}


int finalize_python() {
    if (main_thread_state != NULL) {
        PyEval_RestoreThread(main_thread_state);
        Py_Finalize();

        main_thread_state = NULL;
        return 0;
    }

    return -1;
}


void py_process_detection(char **results,
			  char *fp_string,
			  char *sni,
			  char *dst_addr_string,
			  int dest_port) {
    
    std::string fp_str(fp_string);
    std::string server_name(sni);
    std::string dest_addr(dst_addr_string);
	
    std::stringstream fp_cache_key_;
    fp_cache_key_ << fp_str << server_name << dest_addr << dest_port;
    std::string fp_cache_key = fp_cache_key_.str();

    pthread_mutex_lock(&lock_fp_cache);
    auto it = fp_cache.find(fp_cache_key);
    pthread_mutex_unlock(&lock_fp_cache);
    if (it != fp_cache.end()) {
        *results = it->second;
    } else {
        const char *fp_str_ = fp_str.c_str();
        const char *server_name_ = server_name.c_str();
        const char *dest_addr_ = dest_addr.c_str();

        PyGILState_STATE cur_state = PyGILState_Ensure();
        process_identification_embed(results, fp_str_, server_name_, dest_addr_, dest_port);
        PyGILState_Release(cur_state);

        pthread_mutex_lock(&lock_fp_cache);
        auto it = fp_cache.find(fp_cache_key);
        if (it == fp_cache.end()) {
	    fp_cache.emplace(fp_cache_key, *results);
        } else {
            free((*results));
            *results = it->second;
        }
        pthread_mutex_unlock(&lock_fp_cache);
    }
}


