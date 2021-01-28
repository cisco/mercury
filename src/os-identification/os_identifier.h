
#ifndef OS_IDENTIFIER_H
#define OS_IDENTIFIER_H

#include <iostream>
#include <fstream>
#include <math.h>
#include <zlib.h>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

#include "datum.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/ostreamwrapper.h"


rapidjson::Document tcp_os_fp_db;
rapidjson::Document tls_os_fp_db;
rapidjson::Document http_os_fp_db;

#ifndef DEFAULT_RESOURCE_DIR
#define DEFAULT_RESOURCE_DIR "/usr/local/share/mercury"
#endif


int gzgetline(gzFile f, std::vector<char>& v) {
    v = std::vector<char>(256);
    unsigned pos = 0;
    for (;;) {
        if (gzgets(f, &v[pos], v.size()-pos) == 0) {
            // EOF
            return 0;
        }
        unsigned read = strlen(&v[pos]);
        if (v[pos+read-1] == '\n') {
            pos = pos + read - 1;
            break;
        }
        pos = v.size() - 1;
        v.resize(v.size() * 2);
    }
    v.resize(pos);
    return 1;
}


int database_init(const char *resource_file, rapidjson::Document &fp_db) {
    fp_db.SetObject();
    rapidjson::Document::AllocatorType& allocator = fp_db.GetAllocator();

    gzFile in_file = gzopen(resource_file, "r");
    if (in_file == NULL) {
        return -1;
    }
    std::vector<char> line;
    while (gzgetline(in_file, line)) {
        std::string line_str(line.begin(), line.end());
        rapidjson::Document fp(&allocator);
        fp.Parse(line_str.c_str());

        fp_db.AddMember(fp["str_repr"], fp, allocator);
    }
    gzclose(in_file);

    return 0;  /* success */
}


struct mercury_record {
    struct datum fp_type;
    struct datum fingerprint;
    struct datum src_ip;
    struct datum event_start;
    bool valid;   // a record is valid only if it contains a fingerprint, src_ip, and event_start

    mercury_record() = default;

    mercury_record(struct datum &d) : fp_type{}, fingerprint{}, src_ip{}, event_start{}, valid{false} {
        parse(d);
    };

    void parse(struct datum &d) {
        valid = false;

        uint8_t next_byte;
        if (d.accept('{')) return;
        if (d.accept_byte((const uint8_t *)"\"}", &next_byte)) return;
        struct datum key;
        if (next_byte == '\"') {
            key.parse_up_to_delim(d, '\"'); // "fingerprints"
            if (key.compare((const unsigned char *)"fingerprints", sizeof("fingerprints")-1) != 0) {
                // fprintf(stderr, "expected \"fingerprints\", got %.*s\n", (int)key.length(), key.data);
                return;
            }
            if (d.accept_byte((const uint8_t *)"\"", &next_byte)) return;
        }
        if (d.accept(':')) return;
        if (d.accept('{')) return;
        if (d.accept('\"')) return;
        fp_type.parse_up_to_delim(d, '\"');  // "tls"/"http"/"tcp"
        if (d.accept('\"')) return;

        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        fingerprint.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;
        if (d.accept('}')) return;

        if (datum_skip_upto_delim(&d, (const unsigned char *)"src_ip", sizeof("src_ip")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        src_ip.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;

        if (datum_skip_upto_delim(&d, (const unsigned char *)"event_start", sizeof("event_start")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        event_start.parse_up_to_delim(d, '}');
        if (d.accept('}')) return;

        valid = true;
    }

    bool is_valid() { return valid; }

    void write_json(FILE *output) {
        if (valid) {
            fprintf(output, "{\"fp_type\":\"%.*s\"", (int)fp_type.length(), fp_type.data);
            fprintf(output, ",\"fingerprint\":\"%.*s\"", (int)fingerprint.length(), fingerprint.data);
            fprintf(output, ",\"src_ip\":\"%.*s\"", (int)src_ip.length(), src_ip.data);
            fprintf(output, ",\"event_start\":%.*s}\n", (int)event_start.length(), event_start.data);
        } else {
            fprintf(stderr, "warning: attempt to write invalid or incomplete mercury_record\n");
        }
    }

};


struct os_result {
    std::string os_name;
    double probability;
};

struct os_classifier {
    double *coefficients;
    double *intercepts;
    std::string *labels;
    int os_len;
    int label_len;
    std::unordered_map<std::string, int> os_map;

    os_classifier() = default;

    os_classifier(const char *os_classifier_file) {
        rapidjson::Document clf_params;

        /* read OS classifiers parameters in rapidjson object */
        std::ifstream ifs {os_classifier_file};
        if (!ifs.is_open()) {
            std::cerr << "Could not open file for reading!\n";
            return ;
        }
        rapidjson::IStreamWrapper isw{ifs};
        clf_params.ParseStream(isw);

        os_len = clf_params["os_len"].GetInt();

        /* read in labels */
        const rapidjson::Value& lbls = clf_params["labels"];
        label_len = lbls.Size();
        labels = new std::string[label_len];
        for (rapidjson::SizeType i = 0; i < lbls.Size(); i++) {
            labels[i] = lbls[i].GetString();
        }

        /* read in intercepts */
        intercepts = new double[label_len];
        const rapidjson::Value& intc = clf_params["intercepts"];
        for (rapidjson::SizeType i = 0; i < intc.Size(); i++) {
            intercepts[i] = intc[i].GetDouble();
        }

        /* read in coefficients */
        coefficients = new double[label_len*os_len*3];
        const rapidjson::Value& cff = clf_params["coefficients"];
        for (rapidjson::SizeType i = 0; i < cff.Size(); i++) {
            const rapidjson::Value& cff_inner = cff[i];
            for (rapidjson::SizeType j = 0; j < cff_inner.Size(); j++) {
                coefficients[i*os_len*3+j] = cff_inner[j].GetDouble();
            }
        }

        /* read in os_map */
        const rapidjson::Value& os_m = clf_params["os_map"];
        for (rapidjson::Value::ConstMemberIterator iter = os_m.MemberBegin(); iter != os_m.MemberEnd(); ++iter){
            os_map[iter->name.GetString()] = iter->value.GetInt();
        }
    };

    void classify(double *features, struct os_result *r) {
        double scores[label_len] = {0};
        double score_sum = 0.0;
        for (int i = 0; i < label_len; i++) {
            scores[i] = intercepts[i];
            for (int j = 0; j < os_len*3; j++) {
                scores[i] += coefficients[i*os_len*3+j]*features[j];
            }
            score_sum += exp(scores[i]);
        }

        double prob = 0.0;
        double tmp_prob;
        int label_idx = 0;
        for (int i = 0; i < label_len; i++) {
            tmp_prob = exp(scores[i])/score_sum;
            if (tmp_prob > prob) {
                prob = tmp_prob;
                label_idx = i;
            }
        }

        r->os_name = labels[label_idx];
        r->probability = prob;
    }

} os_clf;


int os_analysis_init(const char *resource_dir) {
    const char *resource_dir_list[] =
      {
       DEFAULT_RESOURCE_DIR,
       "resources",
       "../resources",
       NULL
      };
    if (resource_dir) {
        resource_dir_list[0] = resource_dir;  // use directory from configuration
        resource_dir_list[1] = NULL;          // fail otherwise
    }

    char resource_file_name[PATH_MAX];

    unsigned int index = 0;
    while (resource_dir_list[index] != NULL) {
        strncpy(resource_file_name, resource_dir_list[index], PATH_MAX-1);
        strncat(resource_file_name, "/fingerprint-db-tcp-os.json.gz", PATH_MAX-1);
        int retcode = database_init(resource_file_name, tcp_os_fp_db);

        strncpy(resource_file_name, resource_dir_list[index], PATH_MAX-1);
        strncat(resource_file_name, "/fingerprint-db-tls-os.json.gz", PATH_MAX-1);
        retcode = database_init(resource_file_name, tls_os_fp_db);

        strncpy(resource_file_name, resource_dir_list[index], PATH_MAX-1);
        strncat(resource_file_name, "/fingerprint-db-http-os.json.gz", PATH_MAX-1);
        retcode = database_init(resource_file_name, http_os_fp_db);

        strncpy(resource_file_name, resource_dir_list[index], PATH_MAX-1);
        strncat(resource_file_name, "/os_detection_model.json", PATH_MAX-1);
        os_clf = os_classifier(resource_file_name);

        if (retcode == 0) {
            return 0;
        }
        index++;  /* try next directory in the list */
    }
    fprintf(stderr, "warning: could not initialize OS analysis module\n");
    return -1;
}


void update_features(double **features, const char *fp_type, const char *str_repr) {
    rapidjson::Value::ConstMemberIterator matcher;
    int multiplier = 0;
    if (strcmp(fp_type, "tcp") == 0) {
        matcher = tcp_os_fp_db.FindMember(str_repr);
        if (matcher == tcp_os_fp_db.MemberEnd()) {
            return ;
        }
    } else if (strcmp(fp_type, "tls") == 0) {
        matcher = tls_os_fp_db.FindMember(str_repr);
        if (matcher == tls_os_fp_db.MemberEnd()) {
            return ;
        }
        multiplier = 1;
    } else if (strcmp(fp_type, "http") == 0) {
        matcher = http_os_fp_db.FindMember(str_repr);
        if (matcher == http_os_fp_db.MemberEnd()) {
            return ;
        }
        multiplier = 2;
    } else {
        return ;
    }

    const rapidjson::Value& fp = (multiplier == 0 ? tcp_os_fp_db[str_repr] :
                                  (multiplier == 1 ? tls_os_fp_db[str_repr] : http_os_fp_db[str_repr]));

    const rapidjson::Value& os_keys = fp["os_info"];
    for (rapidjson::Value::ConstMemberIterator iter = os_keys.MemberBegin(); iter != os_keys.MemberEnd(); ++iter){
        const char* os_name = iter->name.GetString();
        double os_perc = iter->value.GetDouble();
        auto it = os_clf.os_map.find(os_name);
        if (it != os_clf.os_map.end()) {
            (*features)[it->second+multiplier*os_clf.os_len] += os_perc;
        }
    }
}


std::unordered_set<std::string> os_fp_types = {"tcp", "tls", "http"};
std::unordered_map<std::string, double*> host_data;
void update_host_data(const char *fp_type, const char *str_repr, const char *src_ip) {
    if (os_fp_types.find(fp_type) == os_fp_types.end()) {
        return ;
    }

    auto it = host_data.find(src_ip);
    if (it == host_data.end()) {
        double *features = new double[os_clf.os_len*3]();
        update_features(&features, fp_type, str_repr);
        host_data[src_ip] = features;
    } else {
        update_features(&it->second, fp_type, str_repr);
    }
}


void os_classify_all_samples() {
    for (auto it = host_data.begin(); it != host_data.end(); ++it) {
        std::cout << "{\"src_ip\":\"" << it->first << "\"";
        double *features = it->second;

        // normalize sample
        double tcp_sum = 0.0, tls_sum = 0.0, http_sum = 0.0;
        for (int i = 0; i < os_clf.os_len; i++) {
            tcp_sum += features[i];
            tls_sum += features[os_clf.os_len+i];
            http_sum += features[os_clf.os_len*2+i];
        }
        for (int i = 0; i < os_clf.os_len; i++) {
            features[i] = (tcp_sum > 0.0) ? features[i]/tcp_sum : features[i];
            features[os_clf.os_len+i] = (tls_sum > 0.0) ? features[os_clf.os_len+i]/tls_sum : features[os_clf.os_len+i];
            features[os_clf.os_len*2+i] = (http_sum > 0.0) ? features[os_clf.os_len*2+i]/http_sum : features[os_clf.os_len*2+i];
        }

        // classify sample
        struct os_result r;
        os_clf.classify(features, &r);
        std::cout << ",\"os\":\"" << r.os_name << "\"";
        std::cout << ",\"probability\":" << r.probability << "}\n";

        delete features;
    }
}


#define FP_BUFFER_SIZE 512
#define FP_TYPE_BUFFER_SIZE 32
#define SRC_IP_BUFFER_SIZE 64
#define EVENT_START_BUFFER_SIZE 32

void os_process_line(std::string line, bool verbose=false) {
    unsigned char *buf = (unsigned char*)line.c_str();
    struct datum d{buf, buf + strlen((char*)buf)};
    struct mercury_record r{d};

    if (!r.is_valid()) {
        if (verbose) {
            fprintf(stderr, "warning: mercury record is invalid or incomplete (%s)\n", line.c_str());
        }
        return;
    }

    char fp_buffer[FP_BUFFER_SIZE];
    char fp_type_buffer[FP_TYPE_BUFFER_SIZE];
    char src_ip_buffer[SRC_IP_BUFFER_SIZE];
    char event_start_buffer[EVENT_START_BUFFER_SIZE];

    snprintf(fp_buffer, FP_BUFFER_SIZE, "%.*s", (int)r.fingerprint.length(), r.fingerprint.data);
    snprintf(fp_type_buffer, FP_TYPE_BUFFER_SIZE, "%.*s", (int)r.fp_type.length(), r.fp_type.data);
    snprintf(src_ip_buffer, SRC_IP_BUFFER_SIZE, "%.*s", (int)r.src_ip.length(), r.src_ip.data);
    snprintf(event_start_buffer, EVENT_START_BUFFER_SIZE, "%.*s", (int)r.event_start.length(), r.event_start.data);

    update_host_data(fp_type_buffer, fp_buffer, src_ip_buffer);
}

#endif /* OS_IDENTIFIER_H */
