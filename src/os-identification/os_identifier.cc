

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unordered_set>
#include <zlib.h>
#include <vector>

#include "../parser.h"
#include "os_identifier.h"

#include "../rapidjson/document.h"
#include "../rapidjson/stringbuffer.h"

rapidjson::Document tcp_os_fp_db;
rapidjson::Document tls_os_fp_db;
rapidjson::Document http_os_fp_db;


unsigned char jbuf[] = "{\"fingerprints\":{\"tls\":\"(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d000e000c050104010201050304030203)(3374)(00100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31)(000500050100000000)(0012))\"},\"tls\":{\"client\":{\"version\":\"0303\",\"random\":\"58ec0e8814ec73ee485e09e3cbb4c05779f1c4673ed534335cb9d027f2a7cbac\",\"session_id\":\"a8201677af1768be3750ed52790188168b0fa976e315434f638e81e9724803cd\",\"cipher_suites\":\"00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a\",\"compression_methods\":\"00\",\"server_name\":\"static.criteo.net\",\"fingerprint\":\"(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d000e000c050104010201050304030203)(3374)(00100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31)(000500050100000000)(0012))\"}},\"src_ip\":\"10.41.32.146\",\"dst_ip\":\"74.119.117.74\",\"protocol\":6,\"src_port\":60034,\"dst_port\":443,\"event_start\":1491865224.241034}";

#ifndef DEFAULT_RESOURCE_DIR
#define DEFAULT_RESOURCE_DIR "/usr/local/share/mercury"
#endif

#define FP_BUFFER_SIZE 512
#define FP_TYPE_BUFFER_SIZE 32
#define SRC_IP_BUFFER_SIZE 64
#define EVENT_START_BUFFER_SIZE 32

std::unordered_set<std::string> os_fp_types = {"tcp", "tls", "http"};

struct os_classifier os_clf;


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


void process_mercury_record(const char *fp_type, const char *str_repr, const char *src_ip, double event_start) {
    rapidjson::Value::ConstMemberIterator matcher;
    rapidjson::Value fp;
    if (strcmp(fp_type, "tcp") == 0) {
        matcher = tcp_os_fp_db.FindMember(str_repr);
        if (matcher == tcp_os_fp_db.MemberEnd()) {
            return ;
        }
        fp = tcp_os_fp_db[str_repr];
    } else if (strcmp(fp_type, "tls") == 0) {
        matcher = tls_os_fp_db.FindMember(str_repr);
        if (matcher == tls_os_fp_db.MemberEnd()) {
            return ;
        }
        fp = tls_os_fp_db[str_repr];
    } else if (strcmp(fp_type, "http") == 0) {
        matcher = http_os_fp_db.FindMember(str_repr);
        if (matcher == http_os_fp_db.MemberEnd()) {
            return ;
        }
        fp = http_os_fp_db[str_repr];
    } else {
        return ;
    }

    int total_count = fp["total_count"].GetInt();
    printf("%d\n", total_count);
    const rapidjson::Value& os_keys = fp["os_info"];

    for (rapidjson::Value::ConstMemberIterator iter = os_keys.MemberBegin(); iter != os_keys.MemberEnd(); ++iter){
        const char* os_name = iter->name.GetString();
        double os_perc = iter->value.GetDouble();
        printf("%s\t", os_name);
        printf("%f\n", os_perc);
    }

    return ;
}


int main(int argc, char *argv[]) {
    os_analysis_init("../../resources");

    struct parser d{jbuf, jbuf + sizeof(jbuf)};
    struct mercury_record r{d};

    char fp_buffer[FP_BUFFER_SIZE];
    char fp_type_buffer[FP_TYPE_BUFFER_SIZE];
    char src_ip_buffer[SRC_IP_BUFFER_SIZE];
    char event_start_buffer[EVENT_START_BUFFER_SIZE];

    snprintf(fp_buffer, FP_BUFFER_SIZE, "%.*s", (int)r.fingerprint.length(), r.fingerprint.data);
    snprintf(fp_type_buffer, FP_TYPE_BUFFER_SIZE, "%.*s", (int)r.fp_type.length(), r.fp_type.data);
    snprintf(src_ip_buffer, SRC_IP_BUFFER_SIZE, "%.*s", (int)r.src_ip.length(), r.src_ip.data);
    snprintf(event_start_buffer, EVENT_START_BUFFER_SIZE, "%.*s", (int)r.event_start.length(), r.event_start.data);
    double event_start = atof(event_start_buffer);

    if (os_fp_types.find(fp_type_buffer) != os_fp_types.end()) {
        printf("%s\n",fp_type_buffer);
        printf("%s\n",fp_buffer);
        printf("%s\n",src_ip_buffer);
        printf("%f\n\n",event_start);

        process_mercury_record(fp_type_buffer, fp_buffer, src_ip_buffer, event_start);
    }

    return 0;
}
