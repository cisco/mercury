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



## References

1. <a name="fireeye"></a>  [FireEye Sunburst Backdoor](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html )
2. <a name="doh"></a> [DNS Queries over HTTPS (RFC 8484)](https://tools.ietf.org/html/rfc8484)
3. <a name="mercury"></a> [Mercury: network metadata capture and analysis](https://github.com/cisco/mercury)
