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

# silce_file <filter> <output file prefix>
#
# takes as input a tshark/wireshark display filter and an associated
# output file prefix, and runs the filter against the input PCAP file,
# to create another PCAP file that contains only packets that match
# the filter, which is named based on the output file prefix
#
function slice_file {
    filter=$1
    outfile="$2.$output"
    if [ ! -f $outfile ]; then
        tshark -r $input -Y $filter -F pcap -w $outfile
    else
        echo "file $outfile exists, skipping"
    fi
}

slice_file "dns.flags.response==1" "dns.query"
slice_file "dns.flags.response==1" "dns.response"
slice_file "http.request"          "http.request"
slice_file "http.response"         "http.response"
slice_file "tls.handshake.type==1" "tls.client_hello"
slice_file "tls.handshake.type==2" "tls.server_hello"
slice_file "dtls.handshake.type==1" "dtls.client_hello"
slice_file "dtls.handshake.type==2" "dtls.server_hello"
slice_file "quic" "quic"                              # TODO: add filter detail

