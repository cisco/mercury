# Mercury: network metadata capture and analysis
<img align="right" src="./mercury.png" width="200">

This package contains two programs for fingerprinting network traffic and capturing and analyzing packet metadata: **mercury**, a Linux application that leverages the modern Linux kernel's high-performance networking capabilities (AF_PACKET and TPACKETv3), which is described below, and [**pmercury**](python/README.md), a portable python application.  There is also a [User's Guide](https://github.com/cisco/mercury/wiki/Using-Mercury).  While mercury is used in some production applications, please consider this software as a 'beta'.  The [CHANGELOG](https://github.com/cisco/mercury/doc/CHANGELOG.md) itemizes changes across different versions.


## Overview

Mercury reads network packets, identifies metadata of interest, and writes out the metadata in JSON format.  Alternatively, mercury can write out the packets that contain the metadata in the PCAP file format.  Mercury can scale up to high data rates (40Gbps on server-class hardware); it uses zero-copy ring buffers to acquire packets, and packets are processed by independent worker threads.  The amount of memory consumed by the ring buffers, and the number of worker threads, are configurable; this makes it easy to scale up (but be wary of using too much memory).

Mercury produces fingerprint strings for TLS, DTLS, SSH, HTTP, TCP, and other protocols; these fingerprints are formed by carefully selecting and normalizing metadata extracted from packets (as documented [here](https://github.com/cisco/mercury/npf.md)).  Fingerprint strings are reported in the "fingerprint" object in the JSON output.  Optionally, mercury can perform process identification based on those fingerprints and the destination context; these results are reported in the "analysis" object.

# Contents

* [Building and installing mercury](#building-and-installing-mercury)
   * [Installation](#installation)
   * [Compile-time options](#compile-time-options)
* [Running mercury](#running-mercury)
  * [Details](#details)
  * [System](#system)
  * [Examples](#examples)
* [Ethics](#ethics)
* [Credits](#credits)
* [Acknowledgements](#acknowledgments)


## Building and installing mercury

Mercury itself has minimal dependencies other than a g++ or llvm build environment, but to run the automated tests and ancillary programs in this package, you will need to install additional packages, as in the following Debian/Ubuntu example:
```
sudo apt install g++ jq git zlib1g-dev tcpreplay valgrind python3-pip libssl-dev clang
pip3 install jsonschema
```
To build mercury, in the root directory, run
```
./configure
make
```
to build the package (and check for the programs and python modules required to test it).  TPACKETv3 is present in Linux kernels newer than 3.2.

### Installation
In the root directory, edit mercury.cfg with the network interface you want to capture from, then run
```
./configure
make

sudo make install MERCURY_CFG=mercury.cfg
```
to install mercury and create and start a systemd service.  If you don't want the mercury systemd service to be installed, then instead run
```
sudo make install-nosystemd
```
The default file and directory locations are
   * __/usr/local/bin/mercury__ for the executable
   * __/usr/local/share/mercury__ for the resource files
   * __/usr/local/var/mercury__ for the output files
   * __/etc/mercury/mercury.cfg__ for the configuration file
   * __/etc/systemd/system/mercury.service__ for the systemd unit file

The output file directory is owned by the user **mercury**; this user is created by the 'make install' target, which must be run as root.  The installation prefix **/usr/local/** can be changed by running ./configure with the --prefix argument, for instance `--prefix=$HOME'.  If you want to install the program somewhere in your home directory, you probably don't want to create the user mercury; you should use the 'make install-nonroot' target, which does not create a user, does not install anything into /etc, and does not install a systemd unit.

The easiest way to run mercury in capture mode is using systemd; the OS automatically starts the mercury systemd unit after each boot, and halts it when the OS is shut down.  To check its status, run
```
systemctl status mercury
```
and the output should contain 'active (running)'.  To view the log (stderr) output from the mercury unit, run
```
sudo journalctl -u mercury
```

To uninstall mercury, run
```
sudo make uninstall
```
which will remove the mercury program, resources directory, user, group, and systemd related files.  The directory containing capture files will be retained, but its owner will be changed to root, to avoid unintentional data loss.  All captured data files are retained across successive installs and uninstalls, and must be manually deleted.

### Compile-time options
To create a debugging version of mercury, use the **make debug-mercury** target in the src/ subdirectory.  Be sure to run **make clean** first.

There are compile-time options that can tune mercury for your hardware.  Each of these options is set via a C/C++ preprocessor directive, which should be passed as an argument to "make" through the OPTFLAGS variable.   Frst run **make clean** to remove the previous build, then run **make "OPTFLAGS=<DIRECTIVE>"**.   This runs make, telling it to pass <DIRECTIVE> to the C/C++ compiler.  The available compile time options are:

   * -DDEBUG, which turns on debugging, and
   * -FBUFSIZE=16384, which sets the fwrite/fread buffer to 16,384 bytes (for instance).
If multiple compile time options are used, then they must be passed to make together in the OPTFLAGS string, e.g. "OPTFLAGS=-DDEBUG -DFBUFSIZE=16384".

## Running mercury
```
mercury: packet metadata capture and analysis
./src/mercury [INPUT] [OUTPUT] [OPTIONS]:
INPUT
   [-c or --capture] capture_interface   # capture packets from interface
   [-r or --read] read_file              # read packets from file
   no input option                       # read packets from standard input
OUTPUT
   [-f or --fingerprint] json_file_name  # write JSON fingerprints to file
   [-w or --write] pcap_file_name        # write packets to PCAP/MCAP file
   no output option                      # write JSON fingerprints to stdout
--capture OPTIONS
   [-b or --buffer] b                    # set RX_RING size to (b * PHYS_MEM)
   [-t or --threads] [num_threads | cpu] # set number of threads
   [-u or --user] u                      # set UID and GID to those of user u
   [-d or --directory] d                 # set working directory to d
GENERAL OPTIONS
   --config c                            # read configuration from file c
   [-a or --analysis]                    # analyze fingerprints
   --resources=f                         # use resource file f
   --stats=f                             # write stats to file f
   --stats-time=T                        # write stats every T seconds
   --stats-limit=L                       # limit stats to L entries
   [-s or --select] filter               # select traffic by filter (see --help)
   --nonselected-tcp-data                # tcp data for nonselected traffic
   --nonselected-udp-data                # udp data for nonselected traffic
   --tcp-reassembly                      # reassemble tcp data segments
   [-l or --limit] l                     # rotate output file after l records
   --output-time=T                       # rotate output file after T seconds
   --dns-json                            # output DNS as JSON, not base64
   --certs-json                          # output certs as JSON, not base64
   --metadata                            # output more protocol metadata in JSON
   [-v or --verbose]                     # additional information sent to stderr
   --license                             # write license information to stdout
   --version                             # write version information to stdout
   [-h or --help]                        # extended help, with examples

DETAILS
   "[-c or --capture] c" captures packets from interface c with Linux AF_PACKET
   using a separate ring buffer for each worker thread.  "[-t or --thread] t"
   sets the number of worker threads to t, if t is a positive integer; if t is
   "cpu", then the number of threads will be set to the number of available
   processors.  "[-b or --buffer] b" sets the total size of all ring buffers to
   (b * PHYS_MEM) where b is a decimal number between 0.0 and 1.0 and PHYS_MEM
   is the available memory; USE b < 0.1 EXCEPT WHEN THERE ARE GIGABYTES OF SPARE
   RAM to avoid OS failure due to memory starvation.

   "[-f or --fingerprint] f" writes a JSON record for each fingerprint observed,
   which incorporates the flow key and the time of observation, into the file f.
   With [-a or --analysis], fingerprints and destinations are analyzed and the
   results are included in the JSON output.

   "[-w or --write] w" writes packets to the file w, in PCAP format.  With the
   option [-s or --select], packets are filtered so that only ones with
   fingerprint metadata are written.

   "[r or --read] r" reads packets from the file r, in PCAP format.

   if neither -r nor -c is specified, then packets are read from standard input,
   in PCAP format.

   "[-s or --select] f" selects packets according to the metadata filter f, which
   is a comma-separated list of the following strings:
      dhcp              DHCP discover message
      dns               DNS messages
      dtls              DTLS clientHello, serverHello, and certificates
      http              HTTP request and response
      http.request      HTTP request
      http.response     HTTP response
      iec               IEC 60870-5-104
      mdns              multicast DNS
      nbns              NetBIOS Name Service
      openvpn_tcp       OpenVPN over TCP
      quic              QUIC handshake
      ssh               SSH handshake and KEX
      smb               SMB v1 and v2
      stun              STUN messages
      ssdp              SSDP (UPnP)
      tcp               TCP headers
      tcp.message       TCP initial message
      tls               TLS clientHello, serverHello, and certificates
      tls.client_hello  TLS clientHello
      tls.server_hello  TLS serverHello
      tls.certificates  TLS serverCertificates
      wireguard         WG handshake initiation message
      all               all of the above
      <no option>       all of the above
      none              none of the above

   --nonselected-tcp-data writes the first TCP Data field in a flow with
   nonzero length, for *non*-selected traffic, into JSON.  This option provides
   a view into the TCP data that the --select option does not recognize. The
   --select filter affects the TCP data written by this option; use
   '--select=none' to obtain the TCP data for each flow.

   --nonselected-udp-data writes the first UDP Data field in a flow with
   nonzero length, for *non*-selected traffic, into JSON.  This option provides
   a view into the UDP data that the --select option does not recognize. The
   --select filter affects the UDP data written by this option; use
   '--select=none' to obtain the UDP data for each flow.

   --tcp-reassembly enables the tcp reassembly
   This option allows mercury to keep track of tcp segment state and 
   and reassemble these segments based on the application in tcp payload

   "[-u or --user] u" sets the UID and GID to those of user u, so that
   output file(s) are owned by this user.  If this option is not set, then
   the UID is set to SUDO_UID, so that privileges are dropped to those of
   the user that invoked sudo.  A system account with username mercury is
   created for use with a mercury daemon.

   "[-d or --directory] d" sets the working directory to d, so that all output
   files are written into that location.  When capturing at a high data rate, a
   high performance filesystem and disk should be used, and NFS partitions
   should be avoided.

   "--config c" reads configuration information from the file c.

   [-a or --analysis] performs analysis and reports results in the "analysis"
   object in the JSON records.   This option only works with the option
   [-f or --fingerprint].

   "[-l or --limit] l" rotates output files so that each file has at most
   l records or packets; filenames include a sequence number, date and time.

   --dns-json writes out DNS responses as a JSON object; otherwise,
   that data is output in base64 format, as a string with the key "base64".

   --certs-json writes out certificates as JSON objects; otherwise,
    that data is output in base64 format, as a string with the key "base64".

   --metadata writes out additional metadata into the protocol JSON objects.

   [-v or --verbose] writes additional information to the standard error,
   including the packet count, byte count, elapsed time and processing rate, as
   well as information about threads and files.

   --license and --version write their information to stdout, then halt.

   [-h or --help] writes this extended help message to stdout.

```

### SYSTEM
The directories used by the default install are as follows.  Run **mercury --help** to
see if the directories on your system differ.
```
   Resource files used in analysis: /usr/local/share/mercury
   Systemd service output:          /usr/local/var/mercury
   Systemd service configuration    /etc/mercury/mercury.cfg
```

### EXAMPLES
```
   mercury -c eth0 -w foo.pcap           # capture from eth0, write to foo.pcap
   mercury -c eth0 -w foo.pcap -t cpu    # as above, with one thread per CPU
   mercury -c eth0 -w foo.mcap -t cpu -s # as above, selecting packet metadata
   mercury -r foo.mcap -f foo.json       # read foo.mcap, write fingerprints
   mercury -r foo.mcap -f foo.json -a    # as above, with fingerprint analysis
   mercury -c eth0 -t cpu -f foo.json -a # capture and analyze fingerprints
```

## Ethics
Mercury is intended for defensive network monitoring, security research and forensics.  Researchers, administrators, penetration testers, and security operations teams can use these tools to protect networks, detect vulnerabilities, and benefit the broader community through improved awareness and defensive posture. As with any packet monitoring tool, Mercury could potentially be misused. **Do not run it on any network of which you are not the owner or the administrator**.

## Credits
Mercury and this package was developed by David McGrew, Brandon Enright, Blake Anderson, Lucas Messenger, Adam Weller, Andrew Chi, Shekhar Acharya, Anastasiia-Mariia Antonyk, Oleksandr Stepanov, Vigneshwari Viswanathan, and Apoorv Raj, with input from Brian Long, Bill Hudson, and others.  Pmercury was developed by Blake Anderson, with input from others.

## Acknowledgments

This package includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

We make use of Mozilla's [Public Suffix List](https://publicsuffix.org/list/) which is subject to the terms of the [Mozilla Public License, v. 2.0](https://mozilla.org/MPL/2.0/).

This package directly incorporates some software made by other
developers, to make the package easier to build, deploy, and run.  We
are grateful to the copyright holders for making their excellent
software available under licensing terms that allow its
redistribution.
   * RapidJSON
      [https://github.com/cisco/mercury/src/rapidjson/license.txt](src/rapidjson/license.txt);
      this package is Copyright 2015 THL A29 Limited, a Tencent company,
      and Milo Yip.
   * lctrie [https://github.com/cisco/mercury/src/lctrie](src/lctrie);
      this package is copyright 2016-2017 Charles Stewart
      <chuckination_at_gmail_dot_com>
