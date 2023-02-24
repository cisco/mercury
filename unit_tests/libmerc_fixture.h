#include "libmerc_driver_helper.hpp"
#include "pcap.h"
#include "packet.h"
#include <filesystem>

using std::filesystem::current_path;

class LibmercTestFixture {
public:
    LibmercTestFixture();
    ~LibmercTestFixture();

protected:
    void initialize();
    void initialize(const struct libmerc_config &config);

    void deinitialize();

    void set_library_path(std::string path);

    void set_time(time_t t);

    void set_pcap(const char * fname);

    int read_next_data_packet();

    int counter();
    int counter(fingerprint_type fp_type, fingerprint_type fp_type2 = fingerprint_type_unknown);
    int counter(fingerprint_type fp_type, std::function<void(const analysis_context*)> callback);
    int counter(fingerprint_type fp_type, std::function<void(const analysis_context*)> callback, uint16_t linktype);
    int counter(fingerprint_type fp_type, std::function<void()> callback);
    
    void check_global_configuraton(libmerc_config config);
    
protected:
    struct libmerc_api * m_mercury;

    mercury_context m_mc;
    mercury_packet_processor m_mpp;
    
    struct timespec m_time;
    std::pair<const uint8_t *, const uint8_t *> m_data_packet;
    struct libmerc_config m_config;
    char m_output[4096];

    std::string m_libmerc_library_path;
    std::string m_path_to_libmerc_alt_library;
    pcap::file_reader *m_pcap;
    packet<65536> m_pkt;
    char * m_pcap_file_name;
    std::string m_pcap_folder_name;
};

struct test_config
{
    struct libmerc_config m_lc;                //libmerc config
    std::string m_pc; //pcap name string config
    fingerprint_type fp_t = fingerprint_type_unknown;
    std::function<void(const analysis_context*)> callback = NULL;
};
