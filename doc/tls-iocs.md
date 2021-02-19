# Using Indicators of Compromise (IoCs) from the Transport Layer Security (TLS) Protocol



The ability to detect compromised systems is essential, and for many incidents, this requires the ability to detect communication with particular Internet hosts.   Some of the most valuable IoCs are the names of servers that control malware, such as "seobundlekit.com" in the recent [Sunburst incident](#fireeye).   These Domain Name System (DNS) names can be observed in several different ways; this note highlights how the traditional approaches to observing DNS names are increasingly less effective, and how other techniques can regain this lost visibility, especially TLS monitoring.



## Using DNS Names as IoCs

Enterprises commonly monitor DNS names by logging queries sent to a DNS server, or relying on a service to perform that logging, or by passively monitoring network traffic and logging the DNS queries observed on the network (called passive DNS, or pDNS for short).    While these techniques are effective, and are considered best practices, they have several blind spots.   The DNS client's operating system caches the responses,  which obscures the number of queries made by the client, which affects both server logging and pDNS.   Server logging suffers from the fact that DNS clients can and do send their queries to *any* DNS server, not just the one sanctioned by the enterprise.   pDNS suffers from the fact that DNS is increasingly being [run over HTTPS](#doh), which hides query names from network security monitoring tools.

### Server Names in TLS

Fortunately, there are other places where we can look for malware server names.  Most Internet communication now takes place over the TLS protocol, which provides the encryption that underlies HTTPS and other protocols.   Server names appear, in unencrypted form, in most TLS sessions, during the handshake phase during which the client and server identify each other, authenticate each other, and agree on the details of the session.   The `client_hello`, the first message that a client sends to a server, often contains the name of the server (in the `server_name` extension).  During that handshake, the server responds with its certificate, which most often contains the server name (in the `subject_alt_name` certificate extension, or in the certificate subject `common_name` field).   These names typically appear in each session, and more directly indicate communication with the server, as opposed to a DNS query.  The TLS protocol has a session resumption feature, the effect of which is similar to DNS caching, but it is often not used.  

In TLSv1.2, all of that data is unencrypted and can readily be parsed by a monitoring system.  In TLSv1.3, the most recent version of that standard, the server_name field in the client_hello is never encrypted, but certificates are encrypted.  However, the certificate associated with a server can easily be obtained by "tailgating": the monitoring system can send its own `client_hello` to the server to obtain the server's certificate, and cache the results for future use.

### Observing Server Names with Mercury

[Mercury](#mercury) can report all of the data fields mentioned above.  These fields appear in the JSON output (when mercury is configured to report that data).   The following table summarizes the fields, where they appear in the JSON, and the command line or configuration file option needed.

| Field Containing Server Name            | Mercury JSON (in [JQ](https://stedolan.github.io/jq/) syntax) | Mercury Option |
| --------------------------------------- | ------------------------------------------------------------ | -------------- |
| DNS query name                          | .`dns.query.question[].name`                                 | `--dns-json`   |
| TLS client hello server_name            | `.tls.client.server_name`                                    | `--metadata`   |
| TLS server certificate subject_alt_name | `.tls.server.certs[].cert.extensions[].subject_alt_name`     | `--certs-json` |
| TLS server certificate common_name      | `.tls.server.certs[].cert.subject[].common_name`             | `--certs-json` |
| HTTP request host name                  | `.http.request.host`                                         | `--metadata`   |

Mercury's JSON corresponds as closely as possible to the original packet data.  Because of this, DNS names have a trailing dot, like "mb.moatads.com.", while TLS server_name fields almost always do not, such as "mb.moatads.com".   (See [RFC 1034](https://www.ietf.org/rfc/rfc1034.txt) and [RFC 6066](https://tools.ietf.org/html/rfc6066#page-6) for details.)  Some TLS clients will put the trailing dot TLS server_name, regardless of the RFC.  The capitalization of DNS names can vary, and may need to be converted to lowercase before comparison (see [RFC 4343](https://tools.ietf.org/html/rfc4343)).  


### Statistics

To quantify the benefits of these additional name sources, we counted the number of distinct names that appeared in each field, for a ten minute period on an enterprise 40 Gbps link.

| Field Containing Server Name | Number of Distinct Names |
| ---------------------------- | ------------------------ |
| DNS query                    | 13,030                   |
| TLS client hello             | 4,121                    |
| TLS certificate              | 14,094                   |

1,203 of the names that appear in the TLS client hellos do *not* appear in the DNS data; this shows that monitoring TLS can find IoCs that would not be found through passive DNS monitoring. 

## Sunburst

The certificate corresponding to the `seobundlekit.com` domain name, which is one of the IoCs for sunburst malware, is:
```javascript
{
  "version": "02",
  "serial_number": "00e578d93f946ead2d4da1a4f79d041d26",
  "signature_identifier": {
    "algorithm": "sha256WithRSAEncryption"
  },
  "issuer": [
    {
      "country_name": "GB"
    },
    {
      "state_or_province_name": "Greater Manchester"
    },
    {
      "locality_name": "Salford"
    },
    {
      "organization_name": "Sectigo Limited"
    },
    {
      "common_name": "Sectigo RSA Domain Validation Secure Server CA"
    }
  ],
  "validity": [
    {
      "not_before": "2020-02-06 00:00:00Z"
    },
    {
      "not_after": "2021-02-05 23:59:59Z"
    }
  ],
  "subject": [
    {
      "common_name": "seobundlekit.com"
    }
  ],
  "subject_public_key_info": {
    "algorithm_identifier": {
      "algorithm": "rsaEncryption"
    },
    "subject_public_key": {
      "modulus": "00b1187fa3abc6eae89ab3429be0de58cc9c5febf94331150488940324afdee213332228926bf3034eca2d16db37337684e29c44dd19df97ccea1ba5682fd0dbf9a57e688eb3918ad725eccd422753aa679f7dfffcaf4a918af4e07ceb1d3eb5f2c1d0eaf13b3268ba7d83382dcf29f60e67ced5aad8dd8fda1aa38f947bf7f9bb3d3c5c9e31b520381e835963b9f0d7139d4df3a00fa77d0cc9bfdba1f13f2275188fcf6590b3e9f16d2fec1866fcea4f817d7b2454a303018881cdfc7ff97262365b84845909b6ad703dd7a1f5a63f70c4eb4ec2aff9edfa1198f7b99f220b8e40b5120bd2c937cf6dc4ffee499082708301593f3ce0799e18b322dd81807fbe0a1877168273a95097d8ac08c5f65fb0ef6bf5f6e4449f9fd4b4db23706d9079eaf6371e2d01216ef3717a23c9203e3391f6a42ed0c00767268ebc03a8c76f6907e683dcaca2d6e35c3abaa7c861e99cf6e98952ca5eee1b861c1a9711c457c002501b82bc9ae1fe0f7fd7f48e9fcaff148db56d92e162ba2eea8b52dafd918def69ce24eba83706dc8b178df51fc48b44fd24e870b9c883a14104c09347cc48f3d4934bcdbab5fb1fa7d79ddb2448b9d75db713c81accd76e503a45995fdd5cc294198b891c7cf8ca3c6cb0ed5e2e9f26da33ae98e7ff7a0f42072a2bd409c50155adc6e3c08e8335df8050e8417443730b51c5bfd833d8f4b3e7c4c6e0e5f9",
      "exponent": "010001",
      "bits_in_modulus": 4096,
      "bits_in_exponent": 17
    }
  },
  "extensions": [
    {
      "authority_key_identifier": {
        "key_identifier": "8d8c5ec454ad8ae177e99bf99b05e1b8018d61e1"
      },
      "critical": false
    },
    {
      "subject_key_identifier": "dd59cc6ff548b6ab52d4aeaafa3a8d2f29ef084b",
      "critical": false
    },
    {
      "key_usage": [
        "digital_signature",
        "key_encipherment"
      ],
      "critical": true
    },
    {
      "basic_constraints": {
        "ca": false,
        "path_len_constraint": 0
      },
      "critical": true
    },
    {
      "ext_key_usage": [
        "id-kp-serverAuth",
        "id-kp-clientAuth"
      ],
      "critical": false
    },
    {
      "certificate_policies": [
        {
          "policy_information": [
            {
              "policy_identifier": "1.3.6.1.4.1.6449.1.2.2.7",
              "policy_qualifier_info": {
                "qualifier_id": "id-qt-cps",
                "qualifier": "https://sectigo.com/CPS"
              }
            }
          ]
        },
        {
          "policy_information": [
            {
              "policy_identifier": "2.23.140.1.2.1"
            }
          ]
        }
      ],
      "critical": false
    },
    {
      "authority_info_access": [
        {
          "access_method": "id-ad-caIssuers",
          "access_location": {
            "uri": "http://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt"
          }
        },
        {
          "access_method": "id-ad-ocsp",
          "access_location": {
            "uri": "http://ocsp.sectigo.com"
          }
        }
      ],
      "critical": false
    },
    {
      "subject_alt_name": [
        {
          "dns_name": "seobundlekit.com"
        },
        {
          "dns_name": "www.seobundlekit.com"
        }
      ],
      "critical": false
    },
    {
      "signed_certificate_timestamp_list": "00f00077007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997e22f0d7000001701a8983ec0000040300483046022100e025f884f1206ac8ec2709d1be42c848f8aa19e915246ba61ed87bdc8679b955022100d640fa13cf0efcc024172f8cba5563d1defad80d5ec32ef802edd3b1ba6d000d0075004494652eb0eeceafc44007d8a8fe28c0dae682bed8cb31b53fd33396b5b681a8000001701a8983d8000004030046304402204a35416f2e405600a192b717633af90a45b6bb5b22b1103ce7b10e26a6067844022065342397c9a81cc0aa1791789dbff6dc4d915dd1c0666d83cba855b090e89003",
      "critical": false
    }
  ],
  "signature_algorithm": {
    "algorithm": "sha256WithRSAEncryption"
  },
  "signature": "bc85aa232bcda856d35e4697e9670bb10aa06fda4c76e2fcaf10ba2de2105cd92aba2690c72a5703e1cd3de683e8466439dab0995120e276937f976abf13f6e3361c5b9e4fb6c6b61eb3a94cdaa40a2eb0ddc9383e9eeac860965a37497aa279b91b1d3ba787ce80d39e9b325dbc1000d8a5e95206acb1f829db3b3ee35100689a51f6e2ed0da537e129c38561ffea6495cff587a1ce54573a7596069edf474eef647e6acdd68766714d31bc305c59f4b11da7ea2585fedb758f891d66277c07228c0b046f57ca800d903b50656d3a28579bd6577eee0ff5ecd827e7841f72eca0271dec2c5287f7249b9cebfe104b5fe4debfd37e814f97f9bdea03bc57af64",
  "bits_in_signature": 2048
}
```

## References

1. <a name="fireeye"></a>  [FireEye Sunburst Backdoor](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html )
2. <a name="doh"></a> [DNS Queries over HTTPS (RFC 8484)](https://tools.ietf.org/html/rfc8484)
3. <a name="mercury"></a> [Mercury: network metadata capture and analysis](https://github.com/cisco/mercury)
