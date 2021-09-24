# Interceptor: a shared object library for plaintext interception

The interceptor library provides deep visibility into the plaintext communication inside of encrypted sessions, by hooking into applications and logging the URLs and host names that those applications visit in their HTTP sessions, along with other data such as DNS queries.  It can also report information about the associated TLS sessions, such as the client fingerprint and the server name. This data is written out in JSON format, with one JSON object per line.  Interceptor is configurable via environment variables, and can write output into a system-wide log file, a user-specified file, or to SYSLOG. The data provided by interceptor can be used for security and privacy research, host security monitoring, troubleshooting, and debugging.

## Building

To build interceptor:

   1.  Check out the mercury using git.
   
   2.  Install prerequisites as needed.  On Debian/Ubuntu:

     $ sudo apt install libssl-dev libnss3-dev libgnutls28-dev

   3.  Run ./configure in the root directory of the mercury package.

   4.  In the src/ subdirectory, run 'make intercept.so'

   5.  Copy intercept.so to some location where it is globally accessible, like /usr/local/lib/.

## Running

To run interceptor:

      1.  In the shell where you want to perform TLS interception, run the command `export LD_PRELOAD=/usr/local/lib/intercept.so`, replacing the path with one appropriate for your system.  This will cause TLS interception for all processes invoked in an environment with this variable set.
   2.  To change interceptor's runtime behavior, set its environment variables.  For instance, to set the directory to which it
       writes its output to `/tmp/intercept`, run `export intercept_dir=/tmp/intercept` in the same shell in which you
       are using it.  The environment variables are listed below.



| Environment Variable   | Values and Defaults                                          | Type    |
| ---------------------- | ------------------------------------------------------------ | ------- |
| intercept_output_type  | `file` (default) writes to `intercept.json`, `log` writes JSON to SYSLOG. | string  |
| intercept_dir          | `path` sets output directory; default=`/usr/local/var/intercept` | string  |
| intercept_output_level | `full` causes process metadata to go into each JSON object   | string  |
| intercept_verbose      | `1` causes verbose output, useful for troubleshooting, debugging, and development | integer |
| intercept_max_pt_len   | no effect at present                                         | integer |

Don't forget to `export` these variables, or to `unset` them when you want to remove a variable that you have previously set and exported.

Output data is written to the directory `/usr/local/var/intercept` (or whatever intercept_dir is set to), and if intercept_verbose is set to 1, or a warning or error condition is encountered, some messages are written to standard error as well.



## Supported Libraries

Function interception is currently implemented for these libraries (listed with their Debian/Ubuntu package names):

* openssl (libssl-dev)            
* NSS (libnss3-dev)           
* GNUtls (libgnutls28-dev)       
  



## Disclaimer

The interceptor library is experimental, and will continue to evolve.  Please do not use it in mission-critical environments.  Feedback is welcome; please send to [mcgrew@cisco.com.](mcgrew@cisco.com).

