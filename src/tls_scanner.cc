//
// tls_scanner.cc
//
// tls_scanner scans an HTTPS server and obtains and reports its TLS
// certificate chain and HTTP response.  It can access domain-fronted
// HTTP servers, and test for domain fronting, when an inner_hostname
// is provided that is distinct from the (outer) hostname.  By
// default, it reports all of the "src=" links in the returned HTML;
// if the HTTP response status code indicates that the resource has
// moved (codes 301 and 302), then the entire response body is printed
// out.  The program is a simple wrapper around the tls_scanner class.

#include <string>
#include <unordered_map>
#include <set>
#include <regex>
#include <array>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "libmerc/x509.h"
#include "libmerc/http.h"
#include "libmerc/json_object.h"

std::array ua_strings = {
                         "Microsoft-CryptoAPI/10.0",
                         "Go-http-client/1.1",
                         "com.apple.trustd/2.0",
                         "Python-urllib/1.17",
                         "dms_api/1.0",
                         "HTTPing v2.4",
                         "HTTPing v2.5",
                         "Microsoft BITS/7.8",
                         "python-requests/2.22.0",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "Microsoft-Delivery-Optimization/10.0",
                         "Prometheus/2.17.2",
                         "avi/1.0",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "Java/11.0.8",
                         "Mozilla/4.7 [en] (X11; U; SunOS 5.6 sun4u)",
                         "Artifactory/6.14.2",
                         "Monit/5.20.0",
                         "Java/1.8.0_112",
                         "Mozilla/4.0 (compatible; ms-office; MSOffice 16)",
                         "FortiGate (FortiOS 6.0) Chrome/ Safari/",
                         "python-requests/2.23.0",
                         "curl/7.66.0",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36",
                         "libwww-perl/6.13",
                         "axios/0.21.1",
                         "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0",
                         "curl/7.47.0",
                         "cisco-IOS",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36",
                         "FlexNet",
                         "curl/7.64.1",
                         "python-requests/2.24.0",
                         "curl/7.29.0",
                         "curl/7.58.0",
                         "ccmhttp",
                         "python-requests/2.21.0",
                         "ConnMan/1.37 wispr",
                         "Microsoft NCSI",
                         "WinHttp-Autoproxy-Service/5.1",
                         "Java/1.8.0_212",
                         "curl/7.50.1",
                         "Fluent-Bit",
                         "Microsoft-WNS/10.0",
                         "Jakarta Commons-HttpClient/3.1",
                         "MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "python-requests/2.15.1",
                         "Apache-HttpClient/4.5.3 (Java/1.8.0_252)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "Python-urllib/3.6",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
                         "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40",
                         "Microsoft-CryptoAPI/6.3",
                         "mimir-api/v1.51.0",
                         "Ruby",
                         "SXM-360L/1.0",
                         "python-requests/2.18.4",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16_0) AppleWebKit/537.36 (KHTML, like Gecko) Brackets/1.13.0 Chrome/51.0.2704.103 Safari/537.36",
                         "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                         "tvoice",
                         "Apache-HttpClient/4.3.6 (java 1.5)",
                         "AHC/1.0",
                         "curl/7.61.1",
                         "Microsoft-CryptoAPI/6.1",
                         "Prometheus/2.21.0",
                         "Mozilla/5.0 (iPhone; CPU iPhone OS 14_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                         "Horizon Camera for eHi",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36 Edg/88.0.705.74",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
                         "curl/7.60.0",
                         "Mono Web Services Client Protocol 4.0.50524.0",
                         "curl/7.54.0",
                         "artifactory-client-java/2.8.3",
                         "libwww-perl/6.04",
                         "python-requests/2.10.0",
                         "urlgrabber/3.10 yum/3.4.3",
                         "AHC/2.1",
                         "GoogleEarth/7.1.0003.0000(MIB;QNX (0.0.0.0);en;kml:2.2;client:Free;type:default)",
                         "CITRIXRECEIVER",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
                         "WebEx/0.0.0.0 (Macintosh; OSX)",
                         "Microsoft BITS/7.7",
                         "Java/1.7.0_45",
                         "Apache-HttpClient/4.5.2 (Java/1.8.0_212)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0",
                         "Python-urllib/3.5",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "Mozilla/5.0",
                         "ConnMan/1.22 wispr",
                         "Dalvik/2.1.0 (Linux; U; Android 5.1.1; Honda Generation 1 mid grade Build/LMY48P)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
                         "SNAP/1.4",
                         "MicroMessenger Client",
                         "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
                         "WebexTeams",
                         "curl/7.67.0",
                         "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "curl/7.28.0",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0",
                         "SFDC-Callout/51.0",
                         "Wget/1.15 (linux-gnu)",
                         "kube-probe/1.17",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
                         "ImmunetProtect/7.2.13.11865",
                         "libwww-perl/6.05",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0",
                         "websocket-sharp/1.0",
                         "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko",
                         "GstpServer/10.15.6.6 macOS Version 10.15.7 (Build 19H114)",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36",
                         "python-requests/2.20.1",
                         "Dalvik/1.6.0 (Linux; U; Android 4.4.2; SAMSUNG-SM-G900A Build/KOT49H)",
                         "Mist-webhook",
                         "Apache-HttpClient/4.5.2 (Java/1.8.0_232)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "python-requests/2.25.1",
                         "python-requests/2.2.1 CPython/2.7.6 Linux/3.13.0-170-generic",
                         "Apache-HttpClient/4.5.12 (Java/1.8.0_212)",
                         "Java/1.8.0_161",
                         "Dalvik/2.1.0 (Linux; U; Android 5.1.1; C401U Build/2050182)",
                         "Java/1.8.0_271",
                         "Debian APT-HTTP/1.3 (1.6.12ubuntu0.2)",
                         "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31",
                         "GstpServer/10.15.6.6 macOS Version 10.14.6 (Build 18G8022)",
                         "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko AnyConnect/4.9.04043 (win)",
                         "Java/1.8.0_192",
                         "EMAN/1.0",
                         "QUECTEL_MODULE",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
                         "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.13530; Pro)",
                         "Axis2",
                         "Dalvik/2.1.0 (Linux; U; Android 8.1.0; C403 Build/3050616)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0",
                         "Apache-HttpClient/4.5.3 (Java/1.8.0_141)",
                         "Mozilla/5.0 (compatible; U; Linux; en-US) WebKit/534.34 (KHTML, like Gecko)",
                         "Mozilla/5.0 (compatible; PRTG Network Monitor (www.paessler.com); Windows)",
                         "Python/3.5 aiohttp/2.2.5",
                         "Typhoeus - https://github.com/typhoeus/typhoeus",
                         "/home/cec/bin/getc3attach C3sr ver. 1.3",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "aws-sdk-java/1.11.764 Linux/3.10.0-1062.9.1.el7.x86_64 OpenJDK_64-Bit_Server_VM/11.0.5+10-alpine-r0 java/11.0.5 groovy/2.5.10 kotlin/1.3.71 vendor/Alpine",
                         "python-requests/2.9.1",
                         "GCSL_GCSP 3.05.4.1615",
                         "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
                         "Facebook",
                         "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.0",
                         "Java/1.7.0_80",
                         "Artifactory/6.23.1",
                         "Microsoft WinRM Client",
                         "python-requests/2.25.0",
                         "Pandora/1.37 Android/6.0.1 gminfo35",
                         "okhttp/4.7.2",
                         "ReactorNetty/0.9.7.RELEASE",
                         "Windows Microsoft Windows 10 Enterprise ZTunnel/1.0",
                         "CaptiveNetworkSupport-407.40.1 wispr",
                         "Python-urllib/2.7",
                         "trustd (unknown version) CFNetwork/902.6 Darwin/17.7.0 (x86_64)",
                         "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.3) Gecko/2008092416 Firefox/3.0.3",
                         "Dalvik/2.1.0 (Linux; U; Android 5.1.1; Acura Infotainment System Build/LMY48P)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041",
                         "Apache-HttpClient/4.5.3 (Java/11.0.3)",
                         "Cisco/CE",
                         "python-requests/2.12.1",
                         "libdnf",
                         "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.18) Gecko/2010020220 Firefox/3.0.18 (.NET CLR 3.5.30729)",
                         "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0",
                         "Digi-Rabbit-httpc/1.08",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
                         "Apache-HttpClient/4.5.9 (Java/1.8.0_144)",
                         "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                         "Apache-HttpClient/4.2.5 (java 1.5)",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36",
                         "urlgrabber/3.9.1 yum/3.2.29",
                         "libwww-perl/6.15",
                         "python-requests/2.18.1",
                         "Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.202 Safari/535.1",
                         "curl/7.19.4 (i386-portbld-freebsd7.2) libcurl/7.19.4 OpenSSL/0.9.8k zlib/1.2.3",
                         "libdnf (CentOS Linux 8; generic; Linux.x86_64)",
                         "WebEx/1.0.0.2 (Windows;)",
                         "GitHub-Hookshot/b64057b",
                         "Debian APT-HTTP/1.3 (1.2.32ubuntu0.2)",
                         "Apache-HttpClient/4.4.1 (Java/1.8.0_252)",
                         "FireAmpLinux/1.12.1.676",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                         "Java/1.8.0_242",
                         "Niagara/3.8.41",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15",
                         "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
                         "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                         "Cisco/M100V (AsyncOS zeus 12.0.0-478)",
                         "McAfee Agent",
                         "Apache-HttpClient/4.5.5 (Java/1.8.0_252)",
                         "python-requests/2.19.1",
                         "ConfdProxyApplication (helm-registry-calls)",
                         "Java/1.8.0_151",
                         "Nessus/8.13.1",
                         "Jetty/9.2.24.v20180105",
                         "WSLib 1.4 [1, 0, 170, 0]",
                         "curl/7.38.0",
                         "Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363",
                         "AivAndroidPlayer/1.0 (AndroidDevice)",
                         "LuaSocket 3.0-rc1",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                         "Java/1.8.0_265",
                         "Java/11.0.2",
                         "check_http/v2.3.3 (nagios-plugins 2.3.3)",
                         "Debian APT-HTTP/1.3 (1.2.31)",
                         "WX2 Atlas Service",
                         "Mozilla/4.0 (compatible; ms-office; MSOffice rmj)",
                         "Mozilla/5.0 (iPhone; CPU iPhone OS 14_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Pandora/2012.1",
                         "Apache-HttpClient/4.3.3 (Java/1.8.0_151)",
                         "Mozilla/5.0 (compatible; pycurl)",
                         "Apache-HttpClient/4.5.10 (Java/11.0.8)",
                         "curl",
                         "Java/1.8.0_222",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36",
                         "AWS Network Health / Contact abuse@amazonaws.com with your website URL to stop",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko)",
                         "libwww-perl/6.03",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; gminfo3 Build/V807-895-P)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; gminfo35 Build/W119E-U148.3.4-MIH20A-523)",
                         "ConfdProxyApplication (helm-calls)",
                         "Pandora/1.37 Android/6.0.1 gminfo3",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
                         "Apache-HttpClient/4.5.3 (Java/11.0.7)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "AppleCoreMedia/1.0.0.18C66 (iPhone; U; CPU OS 14_3 like Mac OS X; en_us)",
                         "Python-urllib/3.8",
                         "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
                         "Java/11.0.10",
                         "elasticsearch-py/7.11.0 (Python 3.7.2)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36",
                         "Java/11.0.9",
                         "Apache-HttpClient/4.5.3 (Java/1.8.0_121)",
                         "Cisco/M100V (AsyncOS zeus 13.6.0-133)",
                         "npm/7.5.6 node/v15.9.0 darwin x64",
                         "Mozilla/5.0 (X11; CrOS x86_64 13505.100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.142 Safari/537.36",
                         "Java/1.8.0_171",
                         "Wget/1.14 (linux-gnu)",
                         "SMS CCM 5.0",
                         "MeDCore",
                         "Dalvik/2.1.0 (Linux; U; Android 5.1.1; C401U Build/2050158)",
                         "Java/1.8.0_232",
                         "Lync/16.0",
                         "Master Admin Router",
                         "Apache-HttpClient/4.5.4 (Java/1.8.0_144)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) svs-camelot-ui/2021.01.11 Chrome/85.0.4183.121 Electron/10.1.5 Safari/537.36",
                         "mod_auth_openidc",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36",
                         "curl/7.63.0",
                         "elasticsearch-py/7.11.0 (Python 3.7.4)",
                         "Telegraf/1.17.2 Go/1.15.5",
                         "Apache-HttpClient/4.5.1 (Java/1.8.0_144)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
                         "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "Dart/1.21 (dart:io)",
                         "Dalvik/2.1.0 (Linux; U; Android 8.1.0; C302U Build/2050612)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
                         "curl/7.59.0",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
                         "Niagara/3.7.46",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:83.0) Gecko/20100101 Firefox/83.0",
                         "Google-HTTP-Java-Client/1.23.0 (gzip)",
                         "curl/7.68.0",
                         "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                         "Apache-HttpClient/4.5.12 (Java/11.0.10)",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; gminfo35 Build/W124E-U150.3.6-MIH20A-529)",
                         "webex utiltp",
                         "Jersey/2.27 (Apache HttpClient 4.5.10)",
                         "curl/7.51.0",
                         "Mozilla/5.0 (iPhone; CPU iPhone OS 14_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Mobile/15E148 Safari/604.1",
                         "Cisco/M100V (AsyncOS zeus 13.6.2-032)",
                         "SplunkStream/7.2.0",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:86.0) Gecko/20100101 Firefox/86.0",
                         "Apache-HttpClient/4.5.5 (Java/1.8.0_212)",
                         "Niagara/3.8.38",
                         "python-requests/2.11.1",
                         "Java/1.8.0_121",
                         "Software%20Update (unknown version) CFNetwork/978.5 Darwin/18.7.0 (x86_64)",
                         "Apache-HttpClient/4.5.1 (Java/1.8.0_232)",
                         "Mozilla/5.0 (X11; CrOS armv7l 11895.142.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.181 Safari/537.36",
                         "Debian APT-HTTP/1.3 (1.0.1ubuntu2)",
                         "IOS_Show_Tech_Parser:103",
                         "python-requests/2.2.1 CPython/2.7.6 Linux/3.13.0-32-generic",
                         "curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.21 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
                         "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.13426; Pro)",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36 Edg/88.0.705.68",
                         "Artifactory/6.12.2",
                         "GCSL_GCSP 3.11.21",
                         "Apache-HttpClient/4.5.3 (Java/1.8.0_202)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                         "axios/0.19.0",
                         "TZMR/3.0 (H3R/v1.9/g1.6-GM)",
                         "python-requests/2.7.0 CPython/2.7.6 Linux/3.13.0-70-generic",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                         "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                         "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                         "Apache-CXF/3.3.3",
                         "GstpServer/11.5.6.6 macOS Version 10.14.6 (Build 18G7016)",
                         "Debian APT-HTTP/1.3 (1.8.2.2)",
                         "iBoot Windex-1.0 iBootOS [ibootG2+] (DataProbe,Inc.)",
                         "Windows-Update-Agent",
                         "Wget/1.19.5 (linux-gnu)",
                         "AirControl Agent v1.0",
                         "AHC/2.0",
                         "QualysGuard",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:84.0) Gecko/20100101 Firefox/84.0",
                         "Datadog Agent/7.22.0",
                         "Mozilla/5.0 (Linux; armv7l GNU/Linux 3.14.43) Sensor-Client-1800S",
                         "Jakarta Commons-HttpClient/3.0.1",
                         "RTKWeb/1.0",
                         "Mozilla/5.0 (compatible; proxytunnel 1.9.0)",
                         "MacOutlook/16.46.21021202 (Intelx64 Mac OS X 11.2.1 (Build 20D74))",
                         "Java/11.0.7",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:86.0) Gecko/20100101 Firefox/86.0",
                         "Java/1.8.0_191",
                         "Jersey/2.25.1 (HttpUrlConnection 1.8.0_212)",
                         "curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.44 zlib/1.2.3 libidn/1.18 libssh2/1.4.2",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
                         "curl/7.64.0",
                         "OfficeClickToRun",
                         "grpc-httpcli/0.0",
                         "Boost.Beast/144",
                         "Avast NCC",
                         "Apache-HttpClient/UNAVAILABLE (java 1.4)",
                         "Dalvik/1.6.0 (Linux; U; Android 4.4.2; C301 Build/2010128)",
                         "Symfony HttpClient/Curl",
                         "Cisco Voice Browser/1.0",
                         "Jersey/2.27 (Apache HttpClient 4.5.6)",
                         "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
                         "1.0,win/10.0.19041,AV/18.5.2342,avl/secline/18.5.3931.0,ffl",
                         "GCSL_GCSP 3.15.6",
                         "Python/3.8 aiohttp/3.6.2",
                         "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                         "Java/1.7.0_261",
                         "$%7BPRODUCT_NAME%7D/$%28CURRENT_PROJECT_VERSION%29 CFNetwork/1209 Darwin/20.2.0",
                         "Apache-HttpClient/4.1.1 (java 1.5)",
                         "BTWebClient/7a5S(45312)",
                         "GoogleEarth/6.2.0002.0000(MIB;QNX (0.0.0.0);en;kml:2.2;client:Free;type:default)",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; gminfo36 Build/W19E-V153.3.8-MIHS21A-53)",
                         "ut_core BenchHttp (ver:45312)",
                         "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
                         "Java/1.8.0_40",
                         "Pandora/1.37 Android/6.0.1 gminfo35 (ExoPlayerLib1.5.2)",
                         "Datadog/Synthetics",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
                         "Java/1.8.0_221",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
                         "RestSharp/106.6.9.0",
                         "MacOutlook/16.45.21011103 (Intelx64 Mac OS X 11.2.1 (Build 20D74))",
                         "Java/1.8.0_91",
                         "couchbase-goxdcr/6.6.0",
                         "Microsoft BITS/7.5",
                         "Mozilla/5.0 (X11; CrOS x86_64 13505.111.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.152 Safari/537.36",
                         " Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
                         "Mesos-DNS",
                         "gSOAP/2.8",
                         "git-lfs/2.12.1 (GitHub; linux amd64; go 1.14.10; git 85b28e06)",
                         "python-requests/2.6.0 CPython/2.7.5 Linux/3.10.0-514.el7.x86_64",
                         "Apache-CXF/3.3.5",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
                         "Apache-HttpClient/4.5.2 (Java/1.8.0_265)",
                         "okhttp/3.12.0",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; gminfo36 Build/W103E-V150.3.1-MIH21A-405.3)",
                         "netdisk;7.0.13.2;PC;PC-Windows;6.1.7601;WindowsBaiduYunGuanJia",
                         "FireAmpLinux/1.9.1.603",
                         "FireAmpLinux/1.10.2.630",
                         "locationd/2245.0.41 CFNetwork/902.1 Darwin/17.7.0 (x86_64)",
                         "Candela OAuth",
                         "Prime%20Video/8.210.6486.6 CFNetwork/1209 Darwin/20.2.0",
                         "Debian APT-HTTP/1.3 (1.2.32ubuntu0.1)",
                         "python-requests/2.17.3",
                         "Microsoft-WNS/6.3",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:84.0) Gecko/20100101 Firefox/84.0",
                         "CCleaner Update Agent",
                         "okhttp/3.8.0",
                         "Telegraf/1.12.4",
                         "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36",
                         "Java/1.8.0_181",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3306.0 Safari/537.36",
                         "$%7BPRODUCT_NAME%7D/$%28CURRENT_PROJECT_VERSION%29 CFNetwork/1220.1 Darwin/20.3.0",
                         "libwww-perl/5.830",
                         "trustd (unknown version) CFNetwork/889.8 Darwin/17.2.0",
                         "libprocess/overlay-master@10.83.92.183:5050",
                         "Apache-HttpClient/4.5.4 (Java/11.0.8)",
                         "Unity Video Lens Remote Scope v0.4",
                         "Zabbix",
                         "Cisco/M100V (AsyncOS zeus 13.6.5-044)",
                         "Apache-HttpClient/4.5.13 (Java/1.8.0_261)",
                         "zsync/0.6.2",
                         "Apache-HttpClient/4.5.2 (Java/1.8.0_181)",
                         "Telegraf/1.12.3",
                         "Wget/1.13.4 (linux-gnu)",
                         "ISUA 12.1305",
                         "Wget/1.11.4",
                         "Calendar Connector",
                         "RestSharp/106.0.0.0",
                         "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
                         "Dalvik/2.1.0 (Linux; U; Android 10; SM-G975U Build/QP1A.190711.020)",
                         "curl/7.69.1",
                         "demalu",
                         "Mozilla/5.0 (iPhone; CPU OS 14_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/14.4 Mobile/10A5355d Safari/8536.25",
                         "couchbase-goxdcr/6.0.0",
                         "elastic/5.0.70 (linux-amd64)",
                         "Debian APT-HTTP/1.3 (2.0.2ubuntu0.2) non-interactive",
                         "Pandora/2012.1 (iPhone; iOS 14.3; Scale/3.00)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nauto 2 Build/MXB48T)",
                         "Pandora/1.37 Android/6.0.1 gminfo36",
                         "axios/0.19.2",
                         "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:45.0) Gecko/20100101 Firefox/45.0",
                         "Apache-HttpClient/4.5.12 (Java/11.0.8)",
                         "Debian APT-HTTP/1.3 (1.4.11)",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
                         "jfrog-mission-control/3.5.3",
                         "FirstFlowAgent",
                         "Windows-RSS-Platform/2.0 (IE 11.0; Windows NT 10.0)",
                         "Expanse indexes the network perimeters of our customers. If you have any questions or concerns, please reach out to: scaninfo@expanseinc.com",
                         "BTWebClient/355S(45852)",
                         "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.1.4322)",
                         "AppleCoreMedia/1.0.0.18G8022 (Macintosh; U; Intel Mac OS X 10_14_6; en_us)",
                         "curl/7.71.1-DEV",
                         "WebEx/1.0.0.1 (Windows;)",
                         "delegate/1.0.55306",
                         "Niagara/3.7.106",
                         "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
                         "Dalvik/2.1.0 (Linux; U; Android 5.1.1; AFTT Build/LVY48F)",
                         "aws-sdk-go/1.8.2 (go1.9; linux; amd64)",
                         "AppleCoreMedia/1.0.0.18C66 (iPad; U; CPU OS 14_3 like Mac OS X; en_us)",
                         "Dalvik/2.1.0 (Linux; U; Android 6.0.1; gminfo36 Build/W19E-V153.3.8-MIHS21B-53)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0",
                         "Software%20Update (unknown version) CFNetwork/1128.0.1 Darwin/19.6.0 (x86_64)",
                         "curl/7.26.0",
                         "Dalvik/2.1.0 (Linux; U; Android 5.1.1; C401E Build/2050158)",
                         "GStreamer souphttpsrc 1.14.4 libsoup/2.62.3",
                         "curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.19.1 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
                         "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "Mojolicious (Perl)",
                         "GLib/2.60",
                         "Java/1.6.0_211",
                         "urlgrabber/3.1.0 yum/3.2.22",
                         "Jersey/2.19 (Apache HttpClient 4.5.10)",
                         "Software%20Update (unknown version) CFNetwork/978.4 Darwin/18.7.0 (x86_64)",
                         "Debian APT-HTTP/1.3 (1.6.12ubuntu0.1)",
                         "Debian APT-HTTP/1.3 (2.0.2ubuntu0.2)",
                         "Apache-HttpClient/4.4.1 (Java/1.8.0_66)",
                         "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15",
                         "npm/6.14.8 node/v12.18.3 linux x64 ci/jenkins",
                         "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
                         "Youdao Desktop Dict (Windows NT 10.0)",
                         "Java/1.8.0_252",
                         "Debian APT-HTTP/1.3 (2.0.4) non-interactive",
                         "SimbeorServer",
                         "python-requests/2.7.0 CPython/2.7.6 Linux/3.19.0-72-generic",
                         "Mozilla/5.0 zgrab/0.x",
                         "wandio/4.2.3",
                         "Debian APT-HTTP/1.3 (1.2.29)",
                         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36",
                         "curl/7.52.1",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
                         "okhttp/3.13.1",
                         "IMInterop Connector",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101",
                         "Wget/1.17.1 (linux-gnu)",
                         "Cisco/M100V (AsyncOS zeus 12.9.14-112)",
                         "Cisco/M100V (AsyncOS zeus 13.6.2-058)",
                         "gSOAP/2.7",
                         "SGOS/6.5.9.10 (600-10; Proxy Edition)",
                         "Cisco/M100V (AsyncOS zeus 12.5.0-683)",
                         "Layer7-SecureSpan-Gateway/v10.0.00-b10442",
                         "Dalvik/2.1.0 (Linux; U; Android 10; SM-G973U Build/QP1A.190711.020)",
                         "Wget",
                         "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.14)",
                         "Java/1.7.0_17",
                         "Java/13.0.2",
                         "curl/7.32.0",
                         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15",
                         "Pandora/1.37 Android/6.0.1 gminfo3 (ExoPlayerLib1.5.2)",
                         "Prometheus/2.23.0",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
                         "Dalvik/2.1.0 (Linux; U; Android 10; SM-G960U Build/QP1A.190711.020)",
                         "Apache-HttpClient/4.5.1 (Java/1.8.0_212)",
                         "Dalvik/2.1.0 (Linux; U; Android 10; SM-N960U Build/QP1A.190711.020)",
                         "Cisco/M100V (AsyncOS zeus 13.6.2-023)",
                         "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
};

class tls_scanner {
private:
    SSL_CTX *ctx = NULL;

    constexpr static const char *tlsv1_3_only_ciphersuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";
    constexpr static const char *user_agent_default = "Mozilla/5.0 (Linux; ; ) AppleWebKit/ (KHTML, like Gecko) Chrome/ Mobile Safari/\r\n"; // pretend we're Android;

    bool print_cert = true;
    bool print_response_body = true;
    bool print_src_links = true;
    std::string user_agent;

public:

    tls_scanner(bool cert, bool response_body, bool src_links) : print_cert{cert}, print_response_body{response_body}, print_src_links{src_links}, user_agent{user_agent_default} { }

    void scan(const std::string &hostname, std::string &inner_hostname, const std::string ua_search_string) {
        std::string &http_host_field = inner_hostname;
        if (inner_hostname == "") {
            http_host_field = hostname;
        }

        // set path, if there is one
        std::string path = "/";
        size_t idx = http_host_field.find("/");
        if (idx != std::string::npos) {
            path = http_host_field.substr(idx, std::string::npos);
            http_host_field.resize(idx);
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
#endif

        // initialize openssl session context
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ctx = SSL_CTX_new(TLSv1_2_client_method());
#else
        ctx = SSL_CTX_new(TLS_client_method());
#endif
        if (ctx == NULL) {
            throw "error: could not initialize TLS context\n";
        }
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            throw "error: could not initialize TLS verification\n";
        }

        std::string host_and_port = http_host_field + ":443";
        BIO *bio = BIO_new_connect(host_and_port.c_str());
        if (bio == nullptr) {
            throw "error: could not create BIO\n";
        }
        if (BIO_do_connect(bio) <= 0) {
            throw "error: could not connect\n";
        }

        BIO *tls_bio = BIO_new_ssl(ctx, 1);
        if (tls_bio == NULL) {
            throw "error: BIO_new_ssl() returned NULL\n";
        }

        BIO_push(tls_bio, bio);

        SSL *tls = NULL;
        BIO_get_ssl(tls_bio, &tls);
        if (tls == NULL) {
            throw "error: could not initialize TLS context\n";
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        constexpr bool tls_version_1_3_only = false;
        if (tls_version_1_3_only) {
            int status = SSL_set_min_proto_version(tls, TLS1_3_VERSION);
            if (status != 1) {
                fprintf(stderr, "warning: could not set protocol version to 1.3 (status=%d)\n", status);
                // throw "error: could not set protocol version to 1.2\n";
            }
        }
#endif

        // status = SSL_set_cipher_list(tls, tlsv1_3_only);
        // if (status != 1) {
        //     fprintf(stderr, "warning: SSL_CTX_set_cipher_list() returned %d\n", status);
        //     // throw "error: could not set TLSv1.3-only ciphersuites\n";
        // }

        SSL_set_tlsext_host_name(tls, http_host_field.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        SSL_set1_host(tls, http_host_field.c_str());
#endif

        if (BIO_do_handshake(tls_bio) <= 0) {
            throw "error: TLS handshake failed\n";
        }

        int err = SSL_get_verify_result(tls);
        if (err != X509_V_OK) {
            const char *message = X509_verify_cert_error_string(err);
            fprintf(stderr, "note: certificate verification failed (%s, code %d)\n", message, err);
        }
        X509 *cert = SSL_get_peer_certificate(tls);
        if (cert == nullptr) {
            fprintf(stderr, "note: server did not present a certificate\n");
        }

        uint8_t *cert_buffer = NULL;
        int cert_len = i2d_X509(cert, &cert_buffer);
        if (print_cert && cert_len > 0) {

            // parse and print certificate using libmerc/asn1/x509.h
            struct x509_cert cc;
            cc.parse(cert_buffer, cert_len);
            cc.print_as_json(stdout);

        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (X509_check_host(cert, hostname.data(), hostname.size(), 0, nullptr) != 1) {
            fprintf(stderr, "note: host verification failed\n");
        }
#else
        // X509_check_host() called automatically
#endif

        if (ua_search_string != "") {
            std::regex ua_regex(ua_search_string);
            for (std::string s : ua_strings) {
                if (std::regex_search(s, ua_regex)) {
                    user_agent = s + "\r\n";
                    fprintf(stderr, "user_agent: \"%s\"\n", s.c_str());
                    break;
                }
            }
        }

        // send HTTP request
        std::string line = "GET " + path + " HTTP/1.1";
        std::string request = line + "\r\n";
        request += "Host: " + http_host_field + "\r\n";
        request += "User-Agent: " + user_agent;
        request += "Connection: close\r\n";
        request += "\r\n";
        //fprintf(stderr, "request: %s\n", request.c_str());
        BIO_write(tls_bio, request.data(), request.size());
        BIO_flush(tls_bio);

        // get HTTP response
        int http_response_len = 0, read_len = 0;
        char http_buffer[1024*256] = {};
        char *current = http_buffer;
        do {
            read_len = BIO_read(tls_bio, current, sizeof(http_buffer) - http_response_len);
            current += read_len;
            http_response_len += read_len;
            //fprintf(stderr, "BIO_read %d bytes\n", read_len);
        } while (read_len > 0 || BIO_should_retry(tls_bio));

        // parse and process http_response message
        if(http_response_len > 0) {

            //fprintf(stdout, "%.*s", http_response_len, http_buffer);

            // parse http headers, and print as JSON
            const unsigned char *tmp = (const unsigned char *)http_buffer;
            struct datum http{tmp, tmp+http_response_len};
            if (true) {
                http_response response;
                response.parse(http);

                char output_buffer[1024*16];
                struct buffer_stream output_buffer_stream{output_buffer, sizeof(output_buffer)};
                struct json_object http_record{&output_buffer_stream};
                response.write_json(http_record);
                http_record.close();
                output_buffer_stream.write_line(stdout);

                struct datum location = response.get_location_header();
                if (location.is_not_empty()) {
                    fprintf(stdout, "location header: %.*s\n", (int)location.length(), location.data);
                }

                if (print_response_body || response.status_code.compare("301", 3) == 0 || response.status_code.compare("302", 3) == 0 ) {
                    // print out redirect data
                    fprintf(stdout, "body: %.*s\n", (int)http.length(), http.data);
                }

            }

            // print out raw body
            //fprintf(stdout, "body: %.*s", (int)http.length(), http.data);

            // find src= links in page
            std::set<std::string> src_links = {};
            std::string http_body = http.get_string();
            std::smatch matches;
            std::regex rgx("src.{2,8}(http(s)*:)*//[a-zA-Z0-9-]*(\\.[a-zA-Z0-9-]*)*");
            while (std::regex_search(http_body, matches, rgx)) {
                // fprintf(stdout, "%s\n", matches[0].str().c_str());
                src_links.insert(matches[0].str());
                http_body = matches.suffix().str();
            }
            for (const auto &x : src_links) {
                if (print_src_links) {
                    fprintf(stdout, "%s\n", x.c_str());
                }
            }
        }
    }

    static void list_user_agents(FILE *f) {
        for (const auto &s : ua_strings) {
            fprintf(f, "\"%s\"\n", s);
        }
    }

};


enum class argument {
    required,
    optional,
    none,
    positional
};

class option {
    std::string name;
    argument arg;
    std::string documentation;
    std::string value;
    bool is_set;

public:
    option(argument opt_arg, std::string opt_name, std::string opt_doc) : name{opt_name}, arg{opt_arg}, documentation{opt_doc}, value{}, is_set{false} { }

    bool matches(const char *option_name) const {
        return name.compare(option_name) == 0;
    }

    bool arg_type(argument a) const { return (a == arg); }

    const char *get_name() const { return name.c_str(); }

    const char *get_doc() const { return documentation.c_str(); }

    std::pair<bool, std::string> get_value() const {
        return {is_set, value};
    }

    void set_value(const char *v) {
        value = v;
        //fprintf(stderr, "setting value %s\n", v);
        is_set = true;
    }

    void set_value() {
        //fprintf(stderr, "setting bool\n");
        is_set = true;
    }

    bool set() { return is_set; }
};

class options {
    std::vector<option> option_vector;

public:
    options(const std::vector<option> &opts) : option_vector{opts} { }

    bool set_positional_parameter(const char *arg) {
        for (option &o : option_vector) {
            if (o.arg_type(argument::positional) && !o.set()) {
                o.set_value(arg);
                return true;
            }
        }
        return false;
    }

    option *find_option_by_name(const char *arg) {
        for (option &o : option_vector) {
            if (o.matches(arg)) {
                //fprintf(stderr, "found option %s\n", arg);
                return &o;
            }
        }
        return nullptr;
    }

    bool string_matches_option_name(const char *arg) {
        for (option &o : option_vector) {
            if (o.matches(arg)) {
                //fprintf(stderr, "string matches option %s\n", arg);
                return true;
            }
        }
        return false;
    }

    bool process_argv(int argc, char *argv[]) {
        if (argc <= 1) {
            return false;  // no options
        }
        argv = &argv[1];  argc--;  // skip program name

        option *last_option = nullptr;
        for (int i=0; i<argc; i++) {
            if (last_option) {
                if (last_option->arg_type(argument::required)) {
                    last_option->set_value(argv[i]);
                    last_option = nullptr;

                } else if (last_option->arg_type(argument::optional)) {
                    if (!string_matches_option_name(argv[i])) {
                        last_option->set_value(argv[i]);
                        last_option = nullptr;
                    }
                }

            } else {
                last_option = find_option_by_name(argv[i]);
                if (last_option == nullptr) {
                    if (!set_positional_parameter(argv[i])) {
                        fprintf(stderr, "error: \"%s\" does not match any option name or positional parameter\n", argv[i]);
                        return false;
                    }
                }
                if (last_option && (last_option->arg_type(argument::none) || last_option->arg_type(argument::optional))) {
                    last_option->set_value();
                    last_option = nullptr;
                }
            }
        }
        if (last_option && last_option->arg_type(argument::required)) {
            fprintf(stderr, "error: option \"%s\" requires an argument\n", last_option->get_name());
            return false;
        }
        return true;
    }

    void usage(FILE *f, const char *progname, const char *summary) {
        fprintf(f, "%s %s", progname, summary);
        for (option &o : option_vector) {
            fprintf(f, "   %s: %s\n", o.get_name(), o.get_doc());
        }
        fputc('\n', f);
    }

    void print_values(FILE *f) {
        fprintf(f, "option values\n");
        for (option &o : option_vector) {
            std::pair<bool, std::string> v = o.get_value();
            if (v.first) {
                fprintf(f, "\t%s", o.get_name());
                if (o.arg_type(argument::required)
                    || o.arg_type(argument::positional)
                    || (o.arg_type(argument::optional) && v.second != "")) {
                    fprintf(f, "\t%s", v.second.c_str());
                }
                fputc('\n', f);
            }
        }
    }

    std::pair<bool, std::string> get_value(const char *name) {
        for (option &o : option_vector) {
            if (o.matches(name)) {
                return o.get_value();
            }
        }
        return { false, "" }; // error: option name not found
    }

    bool is_set(const char *name) {
        for (option &o : option_vector) {
            if (o.matches(name)) {
                return o.set();
            }
        }
        return false;  // error: option name not found
    }

};

/*
 * TODO:
 *
 * - detect ambiguous situations, such as argument::optional that
 *    appear before positional parameters
 */


/*
 * example use of class options
 *
 *    class options opt({{ argument::required,   "--one",     "first argument" },
 *                       { argument::none,       "--two",     "second argument" },
 *                       { argument::positional, "position1", "first positional" },
 *                       { argument::positional, "position2", "second positional" },
 *                       { argument::optional,   "--three",   "third argument" }});
 *
 */

int main(int argc, char *argv[]) {

    const char summary[] =
        "usage:\n"
        "\ttls_scanner <hostname>[/<path>] [OPTIONS]\n"
        "or\n"
        "\ttls_scanner <hostname> <inner_hostname>[/<path>] [OPTIONS]\n"
        "where <path> is the path used in the HTTP URI (e.g. /en-us/)\n\n"
        "Scans an HTTPS server for its certificate, HTTP response headers, response\n"
        "body, redirect links, and src= links, and reports its findings to standard\n"
        "output.  To check for domain fronting, set the inner_hostname to be\n"
        "distinct from hostname.\n\n"
        "OPTIONS\n";

    class options opt({ { argument::positional, "hostname",           "is the name of the HTTPS host (e.g. example.com)" },
                        { argument::positional, "inner_hostname",     "determines the name of the HTTP host field" },
                        { argument::required,   "--user-agent",       "sets the user agent string" },
                        { argument::none,       "--list-user-agents", "print out all user agent strings" },
                        { argument::none,       "--certs",            "prints out server certificate(s) as JSON" },
                        { argument::none,       "--body",             "prints out HTTP response body" }});

    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ hostname_is_set, hostname ] = opt.get_value("hostname");
    auto [ inner_hostname_is_set, inner_hostname ] = opt.get_value("inner_hostname");
    auto [ ua_is_set, ua_search_string ] = opt.get_value("--user-agent");
    bool list_uas    = opt.is_set("--list-user-agents");
    bool print_certs = opt.is_set("--certs");
    bool print_body  = opt.is_set("--body");

    //fprintf(stdout, "openssl version number: %08x\n", (unsigned int)OPENSSL_VERSION_NUMBER);

    if (list_uas) {
        tls_scanner::list_user_agents(stdout);
        return 0;
    }

    if (!hostname_is_set) {
        fprintf(stderr, "error: no hostname provided on command line\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }
    try {
        tls_scanner scanner(print_certs, // print certificate
                            print_body, // print response body
                            true  // print src links
                            );
        scanner.scan(hostname, inner_hostname, ua_search_string);
    }
    catch (const char *s) {
        fprintf(stderr, "%s", s);
    }
    return 0;

}
