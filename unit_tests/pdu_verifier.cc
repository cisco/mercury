#include <cstdio>
#include <libmerc.h>
#include <dlfcn.h>
#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <utility>
#include <getopt.h>

void print_usage()
{
    printf("Usage : verifier -r [pcap to read] -f [filter] [OPTIONS]\n" 
           "Options : \n"
           "\t-w [pcap to write] - write all parsed packets to [pcap to write]\n"
           "\t-p [number] - print HEX data, [number] declares first N bytes to print\n"
           "\t-h [file] - print hex data to [file]\n"
           "\t-s - process output only for successfully parsed packets\n");
}

[[noreturn]] void print_usage_and_fail()
{
    print_usage();
    exit(EXIT_FAILURE);
}

[[noreturn]] void print_error_and_fail(const char* error)
{
    printf("Error:\n\t%s", error);
    exit(EXIT_FAILURE);
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

    static struct option long_opts[] = {
        {"read", required_argument, NULL, 'r'},
        {"filter", required_argument, NULL, 'f'},
        {"write", required_argument, NULL, 'w'},
        {"print", optional_argument, NULL, 'p'},
        {"hex", required_argument, NULL, 'h'},
        {"success", no_argument, NULL, 's'}
    };

    int c = 0;
    int k = 0;

    while(1)
    {
        c = getopt_long(argc, argv, "r:f:w:p:h:s", long_opts, &k);
        if(c < 0)
            break;
        switch (c)
        {
        case 'r':
            if(!optarg)
                print_usage_and_fail();
            _read_file = optarg;
            break;
        case 'f':
            if(!optarg)
                print_usage_and_fail();
            _filter = optarg;
            break;
        case 'w':
            if(!optarg)
                print_usage_and_fail();
            _write_file = optarg;
            break;
        case 'p':
            _analyze_bits = true;
            _printable_size = optarg == nullptr ? 64 : atoi(optarg);
            _printable_size = _printable_size / 2;
            break;
        case 'h':
            if(!optarg)
                print_usage_and_fail();
            _analyze_bits = true;
            _hex_file = optarg;
            break;
        case 's':
            _separate_output = true;
            break;
        default:
            break;
        }
    }

    if(_filter == nullptr || _read_file == nullptr)
    {
        print_usage_and_fail();
    }

    if(_printable_size == 0)
    {
        _printable_size = 32;
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
    config.resources = (char *)"../resources/resources.tgz";
    config.packet_filter_cfg = _filter;

    auto context = mercury_init(&config, 0);
    if(context == nullptr)
        print_error_and_fail("Cannot init mercury with provided config");
    auto packet_processor = mercury_packet_processor_construct(context);
    if(packet_processor == nullptr)
        print_error_and_fail("Cannot create packet processor");

    struct timespec time;
    time.tv_nsec = 0;
    time.tv_sec = 0;

    pcap::file_reader _pcap(_read_file);
    pcap::file_reader* _unmatched_pcap = nullptr;
    if(_write_file != nullptr)
    {
        _unmatched_pcap = new pcap::file_writer(_write_file);
    }

    packet<65536> pkt;

    int found_fp_count = 0;
    int uknown_fp_count = 0;
    int overall_packet_count = 0;

    FILE* _hex_output = nullptr;

    if(_hex_file != nullptr)
    {
        _hex_output = fopen(_hex_file, "w");
        if(_hex_output == nullptr)
            print_error_and_fail("Cannot open hex file");
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
        if((!(!_separate_output != !success)) && (_unmatched_pcap != nullptr))
            _unmatched_pcap.write(data_packet, 0, 0, 0);
    }

    mercury_packet_processor_destruct(packet_processor);
    mercury_finalize(context);

    if(_unmatched_pcap)
    {
        delete _unmatched_pcap;
    }
    if(_hex_output)
    {
        fclose(_hex_output);
    }

    printf("\nParsed %d packets : \n\t Found %d requested pdu's \n\t Parsed %d unknown pdu's\n", overall_packet_count, found_fp_count, uknown_fp_count);

    if(overall_packet_count != found_fp_count)
    {
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
