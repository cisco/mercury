Interceptor: a shared object library for plaintext interception

The interceptor library provides deep visibility into the plaintext
communication inside of encrypted sessions, by hooking into
applications and logging the URLs and host names that those
applications visit in their HTTP sessions, along with other data such
as DNS queries.  It can also report information about the associated
TLS sessions, such as the client fingerprint and the server name.
This data is written into a file in JSON format, with one JSON object
per line.  Interceptor is configurable via environment variables.

The data provided by interceptor can be used for host security
monitoring, troubleshooting and debugging, security and privacy
research, and forensics.

To build interceptor:

   1.  Check out the 'intercept' branch of mercury at
   wwwin-github.cisco.com/network-intelligence/mercury-transition

   2.  Install prerequisites as needed.  On Debian/Ubuntu:

     $ sudo apt install libssl-dev libnss3-dev libgnutls28-dev

   3.  Run ./configure in the root directory of the mercury package.

   4.  In the src/ subdirectory, run 'make intercept.so'

   5.  Copy intercept.so to some location where it is globally
       accessible, like /usr/local/lib/.

To run interceptor:

   1.  In the shell where you want to perform TLS interception, run
       the command `export LD_PRELOAD=/usr/local/lib/intercept.so`,
       replacing the path with one appropriate for your system.  This
       will cause TLS interception for all processes invoked in an
       environment with this variable set.

   2.  To change interceptor's runtime behavior, set its environment
       variables.  For instance, to set the directory to which it
       writes its output to /tmp/intercept, run 'export
       intercept_dir=/tmp/intercept' in the same shell in which you
       are using it.  The environment variables are listed below.


       Environment Variable    Default Value              Type

       -----------------------------------------------------------

       intercept_dir           /usr/local/var/intercept   String

       intercept_verbose       0                          Integer

       intercept_max_pt_len    0                          Integer

       intercept_output_level  minimum or full            String



Don't forget to 'export' these variables, or to 'unset' them when you
want to remove a variable that you have previously set and exported.

Output data is written to the directory /usr/local/var/intercept (or
whatever intercept_dir is set to), and if intercept_verbose is set to
1 or a warning or error condition is encountered, some messages are
written to standard error as well.

Function interception is implemented for these libraries:

    Library     Debian/Ubuntu Package

    -----------------------------------

    openssl     libssl-dev

    NSS         libnss3-dev

    GNUtls      libgnutls28-dev


The interceptor library is experimental, and will continue to evolve.
Please do not use it in mission-critical environments.  Feedback is
welcome; please send to mcgrew@cisco.com.

