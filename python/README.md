# pmercury

pmercury provides a Python reference implementation for network fingerprinting and advanced analysis techniques. As an example, the code can generate a TLS fingerprint given a network interface or packet capture file, and then leverage the provided fingerprint database to perform process identification.

There are four distinct (but related) components:

* protocols/&ast;.pyx - A Python libraries providing APIs for fingerprint generation and inferencing
* pmercury - A wrapper around protocols/&ast;.pyx that can process pcaps or listen to a network interface
* ../src/python-inference/&ast; - A Cython port of protocols/tls.pyx that can be called from C++14 or higher code (and is used to perform process inference in mercury)
* ../resources/fingerprint_db.json.gz - The star of the show; a detailed database associating billions of network and endpoint observations

## Installation

pmercury depends on libpcap-dev:

```bash
sudo apt-get install libpcap-dev
```

On Linux and Python 3.6 and 3.7, install pmercury with pip:

```bash
pip3 install pmercury
```

To build cython extensions:

```bash
python setup.py build_ext --inplace
```

To install pmercury:

```bash
python setup.py install
```

## pmercury

pmercury is designed to highlight the functionality of the protocol classes and to provide a simple interface into the fingerprint database.


### Dependencies

pmercury requires Python 3.6+ along with the following packages:

```bash
pip3 install pyasn
pip3 install hpack
pip3 install pypcap
pip3 install pyyaml
pip3 install cryptography

pip3 install pyasn hpack pypcap pyyaml cryptography
```

pip3 can be installed with 'sudo apt install python3-pip’ on debian/ubuntu, or the equivalent command for your OS.

### Usage

```bash
./pmercury [OPTIONS] [INPUT] [OUTPUT]

INPUT
   [-c or --capture] capture_interface          # live packet capture
   [-r or --read] read_file_name                # read packets from file
   [-d or --fp_db] fingerprint_database         # fingerprint database file (if you are not using the default)

OUTPUT
   [-f or --fingerprint] fingerprint_file_name  # write fingerprints to file (stdout is the default)

OPTIONS
   [-l or --lookup]                             # return database entry for a double quoted fingerprint string
   [-n or --num-procs]                          # return the top-n most probable processes
   [-s or --sslkeylogfile]                      # filename of sslkeylog output for decryption

FLAGS
   [-a or --analysis]                           # perform process identification
   [-w or --human-readable]                     # return human readable fingerprint string
   [-g or --group-flows]                        # aggregate packet-based fingerprints to flow-based
   [-e or --endpoint]                           # aggregate packet-based fingerprints to endpoint-based
   [-x or --experimental]                       # turns on all experimental features
   [-h or --help]                               # help text
```

The input can be either a list of packet capture files or a network interface.

A default fingerprint database is supplied in the resources directory. Updating the repository is currently the only way to get the latest generated database. If you specify your own database, there may be some problems if the formatting is not as expected. Please raise an issue if this is an important use case for you.

The -a switch tells pmercury to perform inferencing on each observed ClientHello packet. The results are comprised of a 4-tuple specifying the name of the process (process) and a score representing the confidence of the algorithm in selecting that process (score).

### Examples

Looking up a fingerprint string in the database:

```bash
~/ $: ./pmercury -l "(0301)(c014c01300390035002fc00ac00900380032000a001300050004)((0000)(000a0006000400170018)(000b00020100)(0017)(ff01))" | jq .
{
  "str_repr": "(0301)(c014c01300390035002fc00ac00900380032000a001300050004)((0000)(000a0006000400170018)(000b00020100)(0017)(ff01))",
  "first_seen": "2019-07-22",
  "last_seen": "2019-07-25",
  "max_implementation_date": "2015-09",
  "min_implementation_date": "1999-01",
  "total_count": 2,
  "process_info": [
    ...
```

Performing process identification:

```bash
~/ $: ./pmercury -r ../test/data/top_100_fingerprints.pcap -a | jq .
{
  "src_ip": "10.0.2.15",
  "dst_ip": "172.217.7.228",
  "src_port": 37582,
  "dst_port": 443,
  "protocol": 6,
  "server_name": "www.google.com",
  "timestamp": "2019-08-06 13:45:51.157055",
  "fingerprints": {
    "tls": "(0303)(c02c...)((0000)...)"
  }
  "analysis": {
    "process": "Microsoft Office (WinNT)",
    "score": 0.9811716395
  }
}
{
  ...
```

### Experimental Features

TLS client fingerprint extraction and process identification is relatively mature. The following are additional pmercury features that either have less thought put into their development, undergone less testing, and/or do not have associated fingerprint databases:

* TLS decryption and fingerprint extraction - Currently decrypts TLS sessions when supplied a file in [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) and extracts the internal HTTP/1.x and HTTP/2 requests and responses.
* TLS server certificate extraction - Currently extracts metadata from the first certificate; no associated auxiliary data.
* SSH server/client fingerprint extraction - Currently extracts metadata from the initial two messages from an SSH client or server.

These features can be turned on by invoking the **-x** option.

To perform decryption with HTTP/2 data extraction:

```bash
~/ $: ./pmercury -r ../test/data/test_decrypt.pcap -s ../test/data/sslkeylogfile.log -w -x
{
  "src_ip": "10.0.2.15",
  "dst_ip": "216.58.194.163",
  "src_port": 46362,
  "dst_port": 443,
  "protocol": 6,
  "event_start": "2019-09-04 16:03:52.933118",
  "fingerprints": {
    "tls_decrypt_h2": "(3a6d6574686f643a20474554)..."
  },
  "tls_decrypt_h2": [
    {":method": "GET"},
    {":authority": "clientservices.googleapis.com"},
    {":scheme": "https"},
    {":path": "/chrome-variations/seed?osname=linux&channel=beta&milestone=76"},
    {"if-none-match": "314f8267d4516ba24ac54575521acebdbe10d2ec"},
    {"a-im": "x-bm,gzip"},
    {"sec-fetch-site": "none"},
    {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.80 Safari/537.36"},
    {"accept-encoding": "gzip, deflate, br"}
  ]
}
```


## protocols/tls.py

tls.py is designed to be a relatively self-contained Python library that provides a rich set of features w.r.t. TLS fingerprinting. The goal is for this library to be as easy as possible to integrate into any Python3 program. Please raise issues if it there are any awkward integration points.

### Dependencies

tls.py requires Python 3.6 along with the following packages:

```bash
sudo pip3 install numpy
sudo pip3 install pyasn
```

### Useful Functions

The TLS class can be instantiated with the following:

```python
tls = TLS(database)
```

tls.py has the ability to extract a fingerprint string from the TCP data associated with a ClientHello. This function will return the fingerprint string and server_name. If the exact fingerprint string was not present in the database, this function will attempt to find and return an approximate match:

```python
def fingerprint(self, data):
    ...
    return protocol_type, fp_str_, approx_str_, server_name
```

Process identification is also handled, and is implemented with the help of lru_cache to improve performance. The function takes a fingerprint string, approximate fingerprint string which can be None, SNI, destination address, destination port, and an optional integer specifying the number of potential processes to return. This function return a dictionary with the inferred process, score, malware indicator, probability of malware, and an optional list of probable processes (probable_processes):

```python
def proc_identify(self, fp_str_, context_, dest_addr, dest_port, list_procs=0):
    server_name = None
    if context_ != None and 'server_name' in context_:
        server_name = context_['server_name']
    # fingerprint approximate matching if necessary
    ...

    return self.identify(fp_str_, server_name, dest_addr, dest_port, list_procs)
```


## protocols/&ast;.py
Other supported protocols in varying stages of development include:
* TCP fingerprint extraction - Currently only based on TCP options; no fingerprint database.
* TLS server fingerprint extraction - Currently only based on ServerHello; no fingerprint database.
* HTTP/1.x client fingerprint extraction - Currently extracts all headers from the HTTP/1.x request; no fingerprint database.
* HTTP/1.x server fingerprint extraction - Currently extracts all headers from the HTTP/1.x response; no fingerprint database.
* DHCP - Currently extracts DHCP options and contextual data; no fingerprint database


## Cython C++ Inferface


## Fingerprint Database

The fingerprint database is a gzipped, 1 JSON object per line file. Each fingerprint contains the following metadata:

```javascript
{
  "str_repr": "(0303)(003d...)((0000)...)", // String representation of the fingerprint
  "first_seen": "2018-06-05",               // Date the fingerprint was first observed
  "last_seen": "2019-08-10",                // Date the fingerprint was last observed
  "max_implementation_date": "2008-08",     // Maximum RFC date that is associated with parameters in the fingerprint
  "min_implementation_date": "2002-06",     // Minimum RFC date that is associated with parameters in the fingerprint
  "total_count": 123,                       // Total number of sessions observed using this fingerprint
  "process_info": [                         // Top-10 most common processes using this fingerprint
    ...
  ]
}
```

Each process object contains some metadata along with objects that represent the destinations the process was observed contacting. The destination information is represented as equivalence classes, e.g., IP addresses are generalized to autonomous systems. For this open source version, the destination information is computed from the top-100 most popular destinations per process.

```javascript
{
  "process": "nmap.exe",         // Name of the process
  "sha256": "F78 ... 99B",       // SHA-256 hash of the process executable
  "count": 10,                   // Total number of sessions observed using this process/fingerprint pair
  "classes_ip_as": {             // Autonomous system equivalence class for IP addresses
    "109:Cisco_Systems": 6,
    ...
  }
  "classes_hostname_tlds": {     // Top level domain equivalence class for server name indication
    "com": 9,
    ...
  }
  "classes_hostname_domains": {  // Domain name equivalence class for server name indication
    "cisco.com": 6,
    ...
  }
  "classes_port_applications": { // Port application equivalence class for port number
    "https": 9,
    ...
  }
  "os_info": {                   // Top-5 most common operating systems observed with this process/fingerprint pair
    "(WinNT)...(10.0.17134)": 8, // (OS)(OS Edition)(OS Version) -> number of sessions
    ...
  }
}
```


## Acknowledgments

This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

We make use of Mozilla's [Public Suffix List](https://publicsuffix.org/list/) which is subject to the terms of the [Mozilla Public License, v. 2.0](https://mozilla.org/MPL/2.0/).
