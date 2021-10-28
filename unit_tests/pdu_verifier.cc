#include <cstdio>
#include <libmerc.h>
#include <dlfcn.h>
#include <pcap_file_io.h>
#include <stdio.h>
#include <cstring>
#include <utility>

int sig_close_flag = false;

void print_usage()
{
    printf("Usage : verifier -r [pcap to read] -f [filter] [OPTIONS]\n" 
           "Options : \n"
           "\t-w [pcap to write] - write all parsed packages to [pcap to write]\n"
           "\t-p [number] - print HEX data, [number] declares first N bytes to print\n"
           "\t-h [file] - print hex data to [file]\n"
           "\t-s - process output only for successfully parsed packages\n");
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
            return EXIT_SUCCESS;
        }
    }

    if(_filter == nullptr || _read_file == nullptr)
    {
        return EXIT_FAILURE;
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
    config.packet_filter_cfg = _filter;

    auto context = mercury_init(&config, 0);
    if(context == nullptr)
        return EXIT_FAILURE;
    auto packet_processor = mercury_packet_processor_construct(context);
    if(packet_processor == nullptr)
        return EXIT_FAILURE;

    struct timespec time;
    time.tv_nsec = 0;
    time.tv_sec = 0;

    struct pcap_file _pcap(_read_file, io_direction_reader);
    struct pcap_file* _unmatched_pcap = nullptr;
    if(_write_file != nullptr)
    {
        _unmatched_pcap = new pcap_file(_write_file, io_direction_writer);
    }
    struct pcap_pkthdr _header;

    packet<65536> pkt;

    int found_fp_count = 0;
    int uknown_fp_count = 0;
    int overall_packet_count = 0;

    FILE* _hex_output = nullptr;

    if(_hex_file != nullptr)
    {
        _hex_output = fopen(_hex_file, "w");
        if(_hex_output == nullptr)
            return EXIT_FAILURE;
    }

    while(1)
    {
        auto data_packet = pkt.get_next(_pcap);
        if(data_packet.first == nullptr || data_packet.second == nullptr)
            break;

        overall_packet_count++;

        char output[4096];

        auto json = mercury_packet_processor_write_json(packet_processor, output, 4096, (unsigned char *)data_packet.first, data_packet.second - data_packet.first, &time);
        bool success = json > 0;

        if(success)
        {
            found_fp_count++;
        }
        else
        {
            uknown_fp_count++;
        }
        if(_analyze_bits && !(!_separate_output != !success))
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
        if((!(!_separate_output == !success)) && (_unmatched_pcap != nullptr))
            pcap_file_write_packet_direct(_unmatched_pcap, data_packet.first, data_packet.second - data_packet.first, 0, 0);

    }

    mercury_packet_processor_destruct(packet_processor);
    mercury_finalize(context);

    if(_unmatched_pcap)
    {
        delete _unmatched_pcap;
    }

    printf("\nParsed %d packets : \n\t Found %d requested pdu's \n\t Parsed %d uknown pdu's\n", overall_packet_count, found_fp_count, uknown_fp_count);

    if(overall_packet_count != found_fp_count)
    {
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}