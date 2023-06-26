# mercury-python

The goal of the `mercury-python` package is to expose mercury's network protocol analysis functionality via python. The cython interface is given in `mercury.pyx`.

## Installation

### Recommended Installation

```bash
pip install mercury-python
```

### From Source

You will first need to [build mercury](https://wwwin-github.cisco.com/network-intelligence/mercury-transition#building-and-installing-mercury)
and install cython and optionally wheel:

```bash
pip install cython
pip install wheel
```

Within mercury's `src/cython/` directory, `Makefile` will build the package based on the makefile target:

```bash
make        # default build in-place
make wheel  # generates pip-installable wheel file
```

## Usage

### Initialization

```python
import mercury

libmerc = mercury.Mercury()                                                            # initialization for packet parsing
libmerc = mercury.Mercury(do_analysis=True, resources=b'/<path>/<to>/<resources.tgz>') # initialization for analysis
```

### Parsing packets

```python
hex_packet = '5254001235020800273a230d08004500...'
libmerc.get_mercury_json(bytes.fromhex(hex_packet))
```

```javascript
{
    "fingerprints": {
        "tls": "tls/(0303)(13011303...)((0000)...)"
    },
    "tls": {
        "client": {
            "version": "0303",
            "random": "0d4e266cf66416689ded443b58d2b12bb2f53e8a3207148e3c8f2be2476cbd24",
            "session_id": "67b5db473da1b71fbca9ed288052032ee0d5139dcfd6ea78b4436e509703c0e4",
            "cipher_suites": "130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a",
            "compression_methods": "00",
            "server_name": "content-signature-2.cdn.mozilla.net",
            "application_layer_protocol_negotiation": [
                "h2",
                "http/1.1"
            ],
            "session_ticket": ""
        }
    },
    "src_ip": "10.0.2.15",
    "dst_ip": "13.249.64.25",
    "protocol": 6,
    "src_port": 32972,
    "dst_port": 443,
}
```


### Analysis

There are two methods to invoke mercury's analysis functionality. The first operates on the full hex packet:

```python
libmerc.analyze_packet(bytes.fromhex(hex_packet))
```

```javascript
{
    "tls": {
        "client": {
            "server_name": "content-signature-2.cdn.mozilla.net"
        }
    },
    "fingerprint_info": {
        "status": "labeled",
        "type": "tls",
        "str_repr": "tls/1/(0303)(13011303...)[(0000)...]"
    },
    "analysis": {
        "process": "firefox",
        "score": 0.9992411956652674,
        "malware": false,
        "p_malware": 8.626882751003134e-06
    }
```

The second method operates directly on the data features (network protocol fingerprint string and destination context):

```python
libmerc.perform_analysis('tls/1/(0303)(13011303...)[(0000)...]', 'content-signature-2.cdn.mozilla.net', '13.249.64.25', 443)
```

```javascript
{
    "fingerprint_info": {
        "status": "labeled"
    },
    "analysis": {
        "process": "firefox",
        "score": 0.9992158715704546,
        "malware": false,
        "p_malware": 8.745628825189023e-06
    }
}
```


### Static functions

Parsing base64 representations of certificate data:

```python
b64_cert = 'MIIJRDC...'
mercury.parse_cert(b64_cert)
```
output:
```javascript
{
    "version": "02",
    "serial_number": "00eede6560cd35c0af02000000005971b7",
    "signature_identifier": {
        "algorithm": "sha256WithRSAEncryption"
    },
    "issuer": [
        {
            "country_name": "US"
        },
        {
            "organization_name": "Google Trust Services"
        },
        {
            "common_name": "GTS CA 1O1"
        }
    ],
    ...
```

Parsing base64 representations of DNS data:

```python
b64_dns = '1e2BgAAB...'
mercury.parse_dns(b64_dns)
```
output:
```javascript
{
    "response": {
        "question": [
            {
                "name": "live.github.com.",
                "type": "AAAA",
                "class": "IN"
            }
        ],
        ...
```

