#/bin/bash
#
# make_test_pcaps.sh
#
# Given a PCAP file as input, creates a set of PCAP files, each of
# which contains a single type of packet.   These files can be used
# for testing protocol recognition and packet processing behavior.

if [ "$#" -ne 1 ]; then
    echo "error: wrong number of arguments"
    echo "usage: $0 <pcapfile>"
    exit -1
fi

input=$1
output=`basename $1`
tshark -r $input -Y "dns.flags.response==0" -F pcap -w dns.query.$output
tshark -r $input -Y "dns.flags.response==1" -F pcap -w dns.response.$output
tshark -r $input -Y "http.request"  -F pcap -w http.request.$output
tshark -r $input -Y "http.response"  -F pcap -w http.response.$output
tshark -r $input -Y "tls.handshake.type==1" -F pcap -w tls.client_hello.$output
tshark -r $input -Y "tls.handshake.type==2" -F pcap -w tls.server_hello.$output
tshark -r $input -Y "quic" -F pcap -w quic.$output


