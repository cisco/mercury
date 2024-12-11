# pmercury

`pmercury` is a tool to process packet captures or listen to a network interface and report JSON records similar to `mercury`. `pmercury` is powered by the cython interface into the core `mercury` code, ensuring consistent behavior between the two programs.

In additional to `pmercury`, this folder contains two tools to facilitate users building a custom `mercury`-compatible resources file that enables process identification:

* `mercury_network_monitor.py`: a data collection tool that associates the process and operating system with network protocol fingerprints and destination context.
* `build_mercury_resources.py`: a tool that operates on `mercury_network_monitor.py` output to build a `mercury`-compatible resources file.


## Dependencies

pmercury requires Python 3.6+ along with the following packages:

```bash
pip3 install pypcap
pip3 install mercury-python
```


## Usage

Basic `pmercury` is similar to `mercury`'s command line functionality:

```bash
usage: pmercury [-h] [-c CAPTURE_INTERFACE] [-r PCAP_FILE] [-f OUTPUT_FILE] [-a] [-x RESOURCES] [-t]

options:
  -h, --help            show this help message and exit
  -c CAPTURE_INTERFACE, --capture CAPTURE_INTERFACE
                        live packet capture
  -r PCAP_FILE, --read PCAP_FILE
                        read packets from file
  -f OUTPUT_FILE, --fingerprint OUTPUT_FILE
                        write fingerprints to file
  -a, --analysis        perform process identification
  --resources RESOURCES
                        use resources file <resources>
  --reassembly          turn on reassembly
```

## Custom Databases

The analysis functionality needs a current resources file that contains a fingerprint database. To facilitate testing, we provide some simple python tools to help collect ground truth and build a resources archive.


### Collecting Ground Truth

`mercury_network_monitor.py` extracts network metadata through the `mercury` cython interface and endpoint metadata (like the process name) through the cross-platform `psutil` python package. Sample usage:

```bash
~/ $: python mercury_network_monitor.py -i <network interface> -o <output directory>
```

To run without root, you may need to give your specific version of python special privileges:

```bash
~/ $: sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip /usr/bin/python3.11
```


### Building a `mercury`-Compatible Resources File

Once `mercury_network_monitor.py` generates a sufficient amount of labeled records, you can then generate a resources file:

```bash
~/ $: python build_mercury_resources.py -d <network monitor output directory> -r <directory to store resources>
```

Within the resources directory that you chose, there will be a `resources-mp.tgz` file, which can be used to enable inline mercury classification:

```bash
~/ $: ../src/mercury -r <pcap file> -f output.json -a --resources=resources/resources-mp.tgz
```