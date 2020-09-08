
#ifndef OS_IDENTIFIER_H
#define OS_IDENTIFIER_H

#include <iostream>
#include <fstream>

#include "../parser.h"

#include "../rapidjson/document.h"
#include "../rapidjson/stringbuffer.h"
#include "../rapidjson/istreamwrapper.h"
#include "../rapidjson/ostreamwrapper.h"


struct mercury_record {
    struct parser fp_type;
    struct parser fingerprint;
    struct parser src_ip;
    struct parser event_start;

    mercury_record() = default;

    mercury_record(struct parser &d) : fp_type{}, fingerprint{}, src_ip{}, event_start{} {
        parse(d);
    };

    void parse(struct parser &d) {
        uint8_t next_byte;
        if (d.accept('{')) return;
        if (d.accept_byte((const uint8_t *)"\"}", &next_byte)) return;
        struct parser key;
        if (next_byte == '\"') {
            key.parse_up_to_delim(d, '\"'); // "fingerprints"
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

        if (parser_skip_upto_delim(&d, (const unsigned char *)"src_ip", sizeof("src_ip")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        src_ip.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;

        if (parser_skip_upto_delim(&d, (const unsigned char *)"event_start", sizeof("event_start")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        event_start.parse_up_to_delim(d, '}');
        if (d.accept('}')) return;
    }

    void write_json(FILE *output) {
        fprintf(output, "{\"fp_type\":\"%.*s\"", (int)fp_type.length(), fp_type.data);
        fprintf(output, ",\"fingerprint\":\"%.*s\"", (int)fingerprint.length(), fingerprint.data);
        fprintf(output, ",\"src_ip\":\"%.*s\"", (int)src_ip.length(), src_ip.data);
        fprintf(output, ",\"event_start\":%.*s}\n", (int)event_start.length(), event_start.data);
    }

};


struct os_classifier {
    double **coefficients;
    double *intercepts;
    std::string *labels;

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

        int os_len = clf_params["os_len"].GetInt();

        /* read in labels */
        const rapidjson::Value& lbls = clf_params["labels"];
        const int label_len = lbls.Size();
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
        coefficients = new double*[label_len];
        for (int i = 0; i < label_len; i++) {
            coefficients[i] = new double[os_len*3];
        }
        const rapidjson::Value& cff = clf_params["coefficients"];
        for (rapidjson::SizeType i = 0; i < cff.Size(); i++) {
            const rapidjson::Value& cff_inner = cff[i];
            for (rapidjson::SizeType j = 0; j < cff.Size(); j++) {
                coefficients[i][j] = cff_inner[j].GetDouble();
            }
        }
    }
};


#endif /* OS_IDENTIFIER_H */
