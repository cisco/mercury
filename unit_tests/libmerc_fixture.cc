#include "libmerc_fixture.h"


LibmercTestFixture::LibmercTestFixture() 
{
    m_pcap_file_name = nullptr;
    m_pcap = nullptr;
    m_libmerc_library_path = LIBMERC_SO_PATH;
}

LibmercTestFixture::~LibmercTestFixture()
{
    if(m_pcap) delete m_pcap;
    if(m_pcap_file_name) free(m_pcap_file_name);
}

void LibmercTestFixture::initialize()
{
    m_mercury = new libmerc_api(m_libmerc_library_path.c_str());
    
    m_mc = m_mercury->init(&m_config, verbosity);

    m_mpp = mercury_packet_processor_construct(m_mc);
}
void LibmercTestFixture::initialize(const struct libmerc_config &config)
{
    m_mercury = new libmerc_api(m_libmerc_library_path.c_str());
    
    m_mc = m_mercury->init(&config, verbosity);

    m_mpp = mercury_packet_processor_construct(m_mc);
}

void LibmercTestFixture::deinitialize()
{
    mercury_packet_processor_destruct(m_mpp);
    mercury_finalize(m_mc);
    if(m_mercury) delete m_mercury;
}

void LibmercTestFixture::check_global_configuraton(struct libmerc_config config)
{
    //check correctness of config set
    CHECK(m_mc->global_vars.dns_json_output == config.dns_json_output);
    CHECK(m_mc->global_vars.do_analysis == config.do_analysis);
    CHECK(m_mc->global_vars.do_stats == config.do_stats);
    CHECK(m_mc->global_vars.enc_key == config.enc_key);
    CHECK(m_mc->global_vars.fp_proc_threshold == config.fp_proc_threshold);
    CHECK(m_mc->global_vars.key_type == config.key_type);
    CHECK(m_mc->global_vars.max_stats_entries == config.max_stats_entries);
    CHECK(m_mc->global_vars.metadata_output == config.metadata_output);
    CHECK(m_mc->global_vars.output_tcp_initial_data == config.output_tcp_initial_data);
    CHECK(m_mc->global_vars.output_udp_initial_data == config.output_udp_initial_data);
    CHECK(m_mc->global_vars.packet_filter_cfg == config.packet_filter_cfg);
    CHECK(m_mc->global_vars.proc_dst_threshold == config.proc_dst_threshold);
    CHECK(m_mc->global_vars.report_os == config.report_os);
    CHECK(m_mc->global_vars.resources == config.resources);
}

void LibmercTestFixture::set_time(time_t t)
{
    m_time.tv_sec = m_time.tv_nsec = t;  // set to January 1st, 1970 (the Epoch)
}

void LibmercTestFixture::set_library_path(std::string path)
{
    m_libmerc_library_path = path;
}

void LibmercTestFixture::set_pcap(const char * fname)
{
    /*to avoid memory leak we need to delete previous record if exist.*/
    if(m_pcap) delete m_pcap; 
    if(m_pcap_file_name) free(m_pcap_file_name);

    const char pcap_f[9] = "./pcaps/";
    if (asprintf(&m_pcap_file_name, "%s%s", pcap_f, fname) < 0) {
        fprintf(stderr, "error in asprintf in %s\n", __func__);
        return; // TODO: indicate error
    }

    printf("\n\n%s\n\n", m_pcap_file_name);
    
    m_pcap = new pcap::file_reader(m_pcap_file_name);
}

int LibmercTestFixture::read_next_data_packet()
{
    m_data_packet = m_pkt.get_next(*m_pcap);
        if(m_data_packet.first == nullptr || m_data_packet.second == nullptr)
        {
            return -1;
        }
    return 0;
}
int LibmercTestFixture::counter()
{
    int count_of_packets = 0;
    while (1)
    {
        if (read_next_data_packet())
            break;

        auto json = mercury_packet_processor_write_json(m_mpp, m_output, 4096,
                                                        (unsigned char *)m_data_packet.first,
                                                        m_data_packet.second - m_data_packet.first,
                                                        &m_time);
        if (json > 0)
            count_of_packets++;
    }
    return count_of_packets;
}

int LibmercTestFixture::counter(fingerprint_type fp_type, fingerprint_type fp_type2)
{
    int count_of_packets = 0;
    while (1)
    {
        if (read_next_data_packet())
        {
            break;
        }

        auto json = mercury_packet_processor_write_json(m_mpp, m_output, 4096, (unsigned char *)m_data_packet.first, m_data_packet.second - m_data_packet.first, &m_time);
        if (json > 0)
        {
            if (m_mpp->analysis.fp.get_type() == fp_type)
                count_of_packets++;
            if(fp_type2 != fingerprint_type_unknown)
                if (m_mpp->analysis.fp.get_type() == fp_type2)
                    count_of_packets++;
        }
    }
    return count_of_packets;
}

int LibmercTestFixture::counter(fingerprint_type fp_type, std::function<void(const analysis_context*)> callback)
{
    int count_of_packets = 0;
    while (1)
    {
        if (read_next_data_packet())
        {
            break;
        }

        const analysis_context *ac = mercury_packet_processor_get_analysis_context(m_mpp, (unsigned char *)m_data_packet.first, m_data_packet.second - m_data_packet.first, &m_time);
        if (ac)
        {
            if (analysis_context_get_fingerprint_type(ac) == fp_type)
            {
                count_of_packets++;
            }
            if (callback)
                callback(ac);
        }
    }
    return count_of_packets;
}

int LibmercTestFixture::counter(fingerprint_type fp_type, std::function<void(const analysis_context*)> callback, uint16_t linktype)
{
    int count_of_packets = 0;
    while (1)
    {
        if (read_next_data_packet())
        {
            break;
        }

        const analysis_context *ac = mercury_packet_processor_get_analysis_context_linktype(m_mpp, (unsigned char *)m_data_packet.first, m_data_packet.second - m_data_packet.first, &m_time, linktype);
        if (ac)
        {
            if (analysis_context_get_fingerprint_type(ac) == fp_type)
            {
                count_of_packets++;
            }
            if (callback)
                callback(ac);
        }
    }
    return count_of_packets;
}

int LibmercTestFixture::counter(fingerprint_type fp_type, std::function<void()> callback)
{
    int count_of_packets = 0;
    while (1)
    {
        if (read_next_data_packet())
        {
            break;
        }
        
        auto json = mercury_packet_processor_write_json(m_mpp, m_output, 4096,
                                                        (unsigned char *)m_data_packet.first,
                                                        m_data_packet.second - m_data_packet.first,
                                                        &m_time);
        if (json > 0) {
            if (m_mpp->analysis.fp.get_type() == fp_type) 
            {
                count_of_packets++;
            
            if (callback)
                callback();
            }
        }
    }
    return count_of_packets;
}
