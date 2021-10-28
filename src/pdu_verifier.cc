#include <cstdio>
#include <libmerc.h>
#include <dlfcn.h>
#include "pcap_file_io.h"
#include <stdio.h>
#include <cstring>
#include <utility>

int sig_close_flag = false;

bool addMockData(std::pair<const uint8_t *, const uint8_t *>& pair);
void filter_switch(char* filter);

uint8_t mock_data[] = { 0x00, 0x50, 0x56, 0xe0, 0xb0, 0xbc, 0x00, 0x0c, 0x29, 0x74, 0x82, 0x2f, 0x08, 0x00, 0x45, 0x00,
                        0x01, 0x60, 0x6f, 0xc4, 0x40, 0x00, 0x40, 0x06, 0xdb, 0x16, 0xc0, 0xa8, 0x71, 0xed, 0xac, 0xd9,
                        0x0f, 0x4e, 0x97, 0x86, 0x01, 0xbb, 0x9c, 0xab, 0xd0, 0xe9, 0x5d, 0x52, 0x12, 0x15, 0x50, 0x18,
                        0xfa, 0xf0, 0xf0, 0x0f, 0x00, 0x00};

void print_usage()
{
    printf("Usage : verifier -r [pcap to read] -w [pcap to write] -f [filter] [OPTIONS]\n" 
           "Options : \n"
           "\t-p - print HEX data\n"
           "\t-h [file] - print hex data to [file]\n"
           "\t-s - process output only for successfully parsed packages\n"
           "Filters: tls-client-hello tls-server-hello http-reqeust http-response + from mercury config\n");
}

int main(int argc, char** argv)
{
    char* _read_file = nullptr;
    char* _write_file = nullptr;
    char* _hex_file = nullptr;
    char* _filter = nullptr;
    uint _printable_size = 0;
    bool _analyze_bits = false;
    bool _separate_output = false;
    bool _tls_client_hello = false;
    bool _tls_server_hello = false;
    bool _http_request = false;
    bool _http_response = false;

    for(int opt_indx = 0; opt_indx < argc; opt_indx++)
    {
        if(strcmp(argv[opt_indx], "-r") == 0)
        {
            _read_file = argv[++opt_indx];
        }
        if(strcmp(argv[opt_indx], "-w") == 0)
        {
            _write_file = argv[++opt_indx];
        }
        if(strcmp(argv[opt_indx], "-f") == 0)
        {
            _filter = argv[++opt_indx];
        }
        if(strcmp(argv[opt_indx], "-p") == 0)
        {
            _analyze_bits = true;
            _printable_size = atoi(argv[opt_indx + 1]) / 2;
            if(_printable_size != 0)
                opt_indx++;
        }
        if(strcmp(argv[opt_indx], "-h") == 0)
        {
            _hex_file = argv[++opt_indx];
        }
        if(strcmp(argv[opt_indx], "-s") == 0)
        {
            _separate_output = true;
        }
        if(strcmp(argv[opt_indx], "--help") == 0)
        {
            print_usage();
            return 0;
        }
    }

    if(_filter == nullptr || _write_file == nullptr || _read_file == nullptr)
    {
        return EXIT_FAILURE;
    }
        

    if(strcmp(_filter, "tls-client-hello") == 0)
    {
        _filter = "tls";
        _tls_client_hello = true;
    }
    else if(strcmp(_filter, "tls-server-hello") == 0)
    {
        _filter = "tls";
        _tls_server_hello = true;
    }
    else if(strcmp(_filter, "tls") == 0)
    {
        _tls_client_hello = true;
        _tls_server_hello = true;
    }
    else if(strcmp(_filter, "http-reqeust") == 0)
    {
        _http_request = true;
        _filter = "http";
    }
    else if(strcmp(_filter, "http-response") == 0)
    {
        _http_response = true;
        _filter = "http";
    }
    else if(strcmp(_filter, "http") == 0)
    {
        _http_response = true;
        _http_request = true;
    }
    else if(strcmp(_filter, "all") == 0)
    {
        _http_response = true;
        _http_request = true;
        _tls_server_hello = true;
        _tls_client_hello = true;
    }

    auto config = libmerc_config();
    config.dns_json_output = true;
    config.certs_json_output = true;
    config.metadata_output = true;
    config.do_analysis = true;
    config.do_stats = true;
    config.report_os = false;
    config.output_tcp_initial_data = false;
    config.output_udp_initial_data = false;
    //config.resources = "./../resources/resources.tgz";
    config.packet_filter_cfg = _filter;

    auto context = mercury_init(&config, 0);
    auto packet_processor = mercury_packet_processor_construct(context);

    size_t len = 0;

    struct timespec time;
    time.tv_nsec = 0;
    time.tv_sec = 0;

    struct pcap_file _pcap(_read_file, io_direction_reader);
    struct pcap_file _unmatched_pcap(_write_file, io_direction_writer);
    struct pcap_pkthdr _header;

    packet<65536> pkt;

    int found_fp_count = 0;
    int uknown_fp_count = 0;
    int overall_packet_count = 0;

    FILE* _hex_output = nullptr;

    if(_hex_file != nullptr)
    {
        _hex_output = fopen(_hex_file, "w");
    }

    while(1)
    {
        auto data_packet = pkt.get_next(_pcap);
        if(data_packet.first == nullptr || data_packet.second == nullptr)
            break;

        overall_packet_count++;

        char output[4096];

        auto json = mercury_packet_processor_write_json(packet_processor, output, 4096, (unsigned char *)data_packet.first, data_packet.second - data_packet.first, &time);

        if(json <= 0 && addMockData(data_packet))
        {
            json = mercury_packet_processor_write_json(packet_processor, output, 4096, (unsigned char *)data_packet.first, data_packet.second - data_packet.first, &time);
        }

        bool success = false;

        do
        {
            if(json > 0)
            {
                if(strstr(output, "{\"fingerprints\":{\"tls\":") != nullptr && !_tls_client_hello)
                    break;
                if(strstr(output, "{\"fingerprints\":{\"tls_server\":") != nullptr && !_tls_server_hello)
                    break;
                if(strstr(output, "{\"fingerprints\":{\"http\":") != nullptr && !_http_request)
                    break;
                if(strstr(output, "{\"fingerprints\":{\"http_server\":") != nullptr && !_http_response)
                    break;
                // auto analys = mercury_packet_processor_get_analysis_context(packet_processor, (unsigned char *)data_packet.first, data_packet.second - data_packet.first, &time);
                // if(analys != nullptr)
                // {
                //     auto fp_type = analysis_context_get_fingerprint_type(analys);
                //     if(fp_type == fingerprint_type_tls && !_tls_client_hello)
                //         break;
                //     if(fp_type == fingerprint_type_tls_server && !_tls_server_hello)
                //         break;
                //     if(fp_type == fingerprint_type_http && !_http_request)
                //         break;
                //     if(fp_type == fingerprint_type_http_server && !_http_response)
                //         break;
                // }
                success = true;
                found_fp_count++;
                if(_analyze_bits && _separate_output)
                {
                    for(int i = 0; data_packet.first + i != data_packet.second; i++)
                    {
                        if(i < _printable_size)
                        {
                            if(_hex_file != nullptr)
                                fprintf(_hex_output, "%02X", *(data_packet.first + i));
                            else
                                printf("%02X", *(data_packet.first + i));
                        }
                        else
                            break;
                    }
                    if(_hex_file != nullptr)
                        fprintf(_hex_output, "\n");
                    else
                        printf("\n");
                }
                if(_separate_output)
                    pcap_file_write_packet_direct(&_unmatched_pcap, data_packet.first, data_packet.second - data_packet.first, 0, 0);
            }
        } while (false);
        
        

        if(!success)
        {
            uknown_fp_count++;
            if(_analyze_bits && !_separate_output)
            {
                for(int i = 0; data_packet.first + i != data_packet.second; i++)
                {
                    if(i < _printable_size)
                    {
                        if(_hex_file != nullptr)
                            fprintf(_hex_output, "%02X", *(data_packet.first + i));
                        else
                            printf("%02X", *(data_packet.first + i));
                    }
                    else
                        break;
                }
                if(_hex_file != nullptr)
                    fprintf(_hex_output, "\n");
                else
                    printf("\n");
            }
            if(!_separate_output)
                pcap_file_write_packet_direct(&_unmatched_pcap, data_packet.first, data_packet.second - data_packet.first, 0, 0);
        }
    }

    mercury_packet_processor_destruct(packet_processor);
    mercury_finalize(context);

    printf("\nParsed %d packets : \n\t Found %d requested pdu's \n\t Parsed %d uknown pdu's\n", overall_packet_count, found_fp_count, uknown_fp_count);

    return 0;
}

uint8_t buffer[2048];
bool addMockData(std::pair<const uint8_t *, const uint8_t *>& pair)
{
    auto pair_size = pair.second - pair.first;
    memcpy(buffer, mock_data, 54);
    memcpy(buffer + 54, pair.first, pair_size);
    pair.first = buffer;
    pair.second = buffer + pair_size + 54;
}