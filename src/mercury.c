/*
 * mercury.c
 *
 * main() file for mercury packet metadata capture and analysis tool
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <dirent.h>
#include "mercury.h"
#include "pcap_file_io.h"
#include "af_packet_io.h"
#include "af_packet_v3.h"
#include "analysis.h"

enum input_mode {
    input_mode_unknown        = 0,
    input_mode_read_file      = 1,
    input_mode_capture        = 2
};

enum output_mode {
    output_mode_unknown       = 0,
    output_mode_pcap_file     = 1,
    output_mode_json          = 2
};

#define TWO_TO_THE_N(N) (unsigned int)1 << (N)


/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
static void sig_close (int signal_arg) {

    printf("\ngot signal %d, shutting down\n", signal_arg);

    analysis_finalize();

    /*
     * the function exit() should invoke fflush() on our output buffers
     */
    exit(0);
}


#define FLAGS_CLOBBER (O_TRUNC)

enum status filename_append(char dst[MAX_FILENAME],
			    const char *src,
			    const char *delim,
			    const char *tail) {

    if (tail) { 

	/*
	 * filename = directory || '/' || thread_num 
	 */	
	if (strnlen(src, MAX_FILENAME) + strlen(tail) + 1 > MAX_FILENAME) {
	    return status_err; /* filename too long */
	}
	strncpy(dst, src, MAX_FILENAME);
	strcat(dst, delim);
	strcat(dst, tail);

    } else {

	if (strnlen(src, MAX_FILENAME) >= MAX_FILENAME) {
	    return status_err; /* filename too long */
	}
	strncpy(dst, src, MAX_FILENAME); 
	
    }
    return status_ok;
}

enum status frame_handler_init_from_config(struct frame_handler *handler,
					   struct mercury_config *cfg,
					   int tnum,
					   char *fileset_id) {
    enum status status;
    char outfile[MAX_FILENAME];
    pid_t pid = tnum; // syscall(__NR_gettid);

    uint64_t max_records = 0;
    if (cfg->rotate) {
	max_records = cfg->rotate;
    }
    
    if (cfg->write_filename) {
	
	status = filename_append(outfile, cfg->write_filename, "/", fileset_id);
	if (status) {
	    return status;
	}	
	if (cfg->verbosity) {
	    printf("initializing thread function %x with filename %s\n", pid, outfile);
	}
	
	if (cfg->filter) {
	    /*
	     * write only TLS clientHellos and TCP SYNs to capture file
	     */
	    status = frame_handler_filter_write_pcap_init(handler, outfile, cfg->flags, cfg->packet_filter_cfg);
	    if (status) {
		return status;
	    }
	} else {
	    /*
	     * write all packets to capture file
	     */
	    status = frame_handler_write_pcap_init(handler, outfile, cfg->flags);
	    if (status) {
		printf("%s: could not open pcap output file %s\n", strerror(errno), outfile);
		return status;
	    }

	}
	
    } else if (cfg->fingerprint_filename) {
	/*
	 * write fingerprints into output file
	 */	
	status = filename_append(outfile, cfg->fingerprint_filename, "/", fileset_id);
	if (status) {
	    return status;
	}
	if (cfg->verbosity) {
	    printf("initializing thread function %x with filename %s\n", pid, outfile);
	}
	
	status = frame_handler_write_fingerprints_init(handler, outfile, cfg->mode, max_records);
	if (status) {
	    perror("error: could not open fingerprint output file");
	    return status;
	}
    } else {
        /*
	 * default: dump JSON-formatted packet info to stdout
	 */
	status = frame_handler_dump_init(handler);
	if (status) {
	    perror("could not initialize frame dump");
	    return status;
	}
	
    }
    
    return status_ok;
}

enum status thread_context_init_from_config(struct thread_context *tc,
					    struct mercury_config *cfg,
					    int tnum,
					    char *fileset_id) {

    enum status status;

    status = frame_handler_init_from_config(&tc->handler, cfg, tnum, fileset_id);
    if (status) {
	return status;
    }
    
    if (cfg->capture_interface) {
	/*
	 * set up input for a network capture 
	 */
	printf("buffer fraction: %e\n", cfg->buffer_fraction);
	status = capture_init(tc, cfg->fanout_group, cfg->buffer_fraction);
	if (status) {
	    perror("could not initialize AF_PACKET socket");
	    return status_err;
	}
    } else {
	return status_err; /* no interface specified */
    }
    
    return status_ok;    
}

void *packet_processing_thread_func(void *userdata) {
    struct thread_context *tc = (struct thread_context *)userdata;
    enum status status;
    
    /*
     * start packet processing loop
     */
    status = capture_loop(tc);
    if (status) {
	perror("failure in capture loop");
	return NULL;
    }
    
    return NULL;
}

void create_subdirectory(const char *outdir,
			 enum create_subdir_mode mode) {
    printf("creating output directory %s\n", outdir);
    if (mkdir(outdir, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
	if (errno == EEXIST && mode == create_subdir_mode_overwrite) {
	    printf("warning: directory %s exists; new data will be written into it\n", outdir);
	} else {
	    printf("error %s: could not create directory %s\n", strerror(errno), outdir);
	    exit(255);
	}
    }
}

/*
 * struct pcap_reader_thread_context holds thread-specific information
 * for a pcap-file-reading thread; it is a sister to struct
 * thread_context, which has the equivalent role for network capture
 * threads
 */
struct pcap_reader_thread_context {
    struct frame_handler handler; 
    int tnum;                 /* Thread Number */
    pthread_t tid;            /* Thread ID */
    struct pcap_file rf;
    int loop_count;           /* loop count */
};

enum status pcap_reader_thread_context_init_from_config(struct pcap_reader_thread_context *tc,
							struct mercury_config *cfg,
							int tnum,
							char *fileset_id) {
    char input_filename[MAX_FILENAME];
    tc->tnum = tnum;
	tc->loop_count = cfg->loop_count;
    
    enum status status = frame_handler_init_from_config(&tc->handler, cfg, tnum, fileset_id);
    if (status) {
	return status;
    }

    status = filename_append(input_filename, cfg->read_filename, "/", fileset_id);
    if (status) {
	return status;
    }	
    
    status = pcap_file_open(&tc->rf, input_filename, io_direction_reader, cfg->flags);
    if (status) {
	printf("%s: could not open pcap input file %s\n", strerror(errno), cfg->read_filename);
	return status;
    }

    return status_ok;
}

void *pcap_file_processing_thread_func(void *userdata) {
    struct pcap_reader_thread_context *tc = (struct pcap_reader_thread_context *)userdata;
    enum status status;
    
    status = pcap_file_dispatch_frame_handler(&tc->rf, tc->handler.func, &tc->handler.context, tc->loop_count);
    if (status) {
	printf("error in pcap file dispatch (code: %d)\n", (int)status);
	return NULL;
    }
    status = pcap_file_close(&tc->rf);
    if (status) {
	printf("error closing pcap file (code: %d)\n", (int)status);
	return NULL;
    }
			     
    return NULL;
}

#define BILLION 1000000000L

static inline void get_clocktime_before (struct timespec *before) {
    if (clock_gettime(CLOCK_REALTIME, before) != 0) {
        // failed to get clock time, set the uninitialized struct to zero
        bzero(before, sizeof(struct timespec));
        perror("error: could not get clock time before fwrite file header\n");
    }
}

static inline uint64_t get_clocktime_after (struct timespec *before,
                                            struct timespec *after) {
    uint64_t nano_sec = 0;
    if (clock_gettime(CLOCK_REALTIME, after) != 0) {
        perror("error: could not get clock time after fwrite file header\n");
    } else {
        // It is assumed that if this call is successful, the previous call is also successful.
        // We got clock time after writting, now compute the time difference in nano seconds
        nano_sec += (BILLION * (after->tv_sec - before->tv_sec)) + (after->tv_nsec - before->tv_nsec);
    }
    return nano_sec;
}

enum status open_and_dispatch(struct mercury_config *cfg) {
    struct stat statbuf;
    enum status status;
    struct timespec before, after;
	u_int64_t nano_seconds = 0;
	u_int64_t bytes_written = 0;
	u_int64_t packets_written = 0;

    get_clocktime_before(&before); // get timestamp before we start processing

    if (cfg->read_filename && stat(cfg->read_filename, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
	DIR *dir = opendir(cfg->read_filename);
	struct dirent *dirent;

	/*
	 * read_filename is a directory containing capture files created by separate threads
	 */

	/*
	 * count number of files in fileset
	 */
	int num_files = 0;
	while ((dirent = readdir(dir)) != NULL) {
		
	    char input_filename[MAX_FILENAME];
	    filename_append(input_filename, cfg->read_filename, "/", dirent->d_name);
	    if (stat(input_filename, &statbuf) == 0) {
		if (S_ISREG(statbuf.st_mode)) {
		    
		    num_files++;
		}
	    } 
	}
	    
	/*
	 * set up thread contexts
	 */
	struct pcap_reader_thread_context *tc = (struct pcap_reader_thread_context *)malloc(num_files * sizeof(struct pcap_reader_thread_context));
	if (!tc) {
	    perror("could not allocate memory for thread storage array\n");
	}

	char *outdir = cfg->fingerprint_filename ? cfg->fingerprint_filename : cfg->write_filename;
	if (outdir) {
	    /*
	     * create subdirectory into which each thread will write its output
	     */
	    create_subdirectory(outdir, create_subdir_mode_do_not_overwrite);
	}

	/*
	 * loop over all files in directory
	 */
	rewinddir(dir);
	int tnum = 0;
	while ((dirent = readdir(dir)) != NULL) {
		
	    char input_filename[MAX_FILENAME];
	    filename_append(input_filename, cfg->read_filename, "/", dirent->d_name);
	    if (stat(input_filename, &statbuf) == 0) {
		if (S_ISREG(statbuf.st_mode)) {
		    
		    status = pcap_reader_thread_context_init_from_config(&tc[tnum], cfg, tnum, dirent->d_name);
		    if (status) {
			perror("could not initialize pcap reader thread context");
			return status;
		    }

		    int err = pthread_create(&(tc[tnum].tid), NULL, pcap_file_processing_thread_func, &tc[tnum]);
		    tnum++;
		    if (err) {
			printf("%s: error creating file reader thread\n", strerror(err));
			exit(255);
		    }

		}

	    } else {
		perror("stat");
	    }

	}

	if (tnum != num_files) {
	    printf("warning: num_files (%d) != tnum (%d)\n", num_files, tnum);
	}

	for (int i = 0; i < tnum; i++) {
	    pthread_join(tc[i].tid, NULL);
		bytes_written += tc[i].rf.bytes_written;
		packets_written += tc[i].rf.packets_written;
	}
		
    } else {

	/*
	 * we have a single capture file, not a directory of capture files
	 */
	struct pcap_reader_thread_context tc;
	    
	enum status status = pcap_reader_thread_context_init_from_config(&tc, cfg, 0, NULL);
	if (status != status_ok) {
	    return status;
	}

	pcap_file_processing_thread_func(&tc);
	bytes_written = tc.rf.bytes_written;
	packets_written = tc.rf.packets_written;
    }

    nano_seconds = get_clocktime_after(&before, &after);
    double byte_rate = ((double)bytes_written * BILLION) / (double)nano_seconds;

    if (cfg->write_filename && cfg->verbosity) {
	printf("For all files, packets written: %lu, bytes written: %lu, nano sec: %lu, bytes per second: %.4e\n",
	       packets_written, bytes_written, nano_seconds, byte_rate);
    }
    
    return status_ok;
}

#define EXIT_ERR 255

char mercury_help[] =
    "%s INPUT [OUTPUT] [OPTIONS]:\n"
    "INPUT\n"
    "   [-c or --capture] capture_interface   # capture packets from interface\n"
    "   [-r or --read] read_file              # read packets from file\n"
    "OUTPUT\n"
    "   [-f or --fingerprint] json_file_name  # write fingerprints to JSON file\n"
    "   [-w or --write] pcap_file_name        # write packets to PCAP/MCAP file\n"
    "   no output option                      # write JSON packet summary to stdout\n"
    "--capture OPTIONS\n"
    "   [-b or --buffer] b                    # set RX_RING size to (b * PHYS_MEM)\n"
    "   [-t or --threads] [num_threads | cpu] # set number of threads\n"
    "   [-u or --user] u                      # set UID and GID to those of user u\n"
    "--read OPTIONS\n"
    "   [-m or --multiple] count              # loop over read_file count >= 1 times\n"
    "GENERAL OPTIONS\n"
    "   [-a or --analysis]                    # analyze fingerprints\n"
    "   [-s or --select]                      # select only packets with metadata\n"
    "   [-l or --limit] l                     # rotate JSON files after l records\n"
    "   [-v or --verbose]                     # additional information sent to stdout\n"
    "   [-h or --help]                        # extended help, with examples\n";

char mercury_extended_help[] =
    "\n"
    "DETAILS\n"
    "   \"[-c or --capture] c\" captures packets from interface c with Linux AF_PACKET\n"
    "   using a separate ring buffer for each worker thread.  \"[-t or --thread] t\"\n"
    "   sets the number of worker threads to t, if t is a positive integer; if t is\n"
    "   \"cpu\", then the number of threads will be set to the number of available\n"
    "   processors.  \"[-b or --buffer] b\" sets the total size of all ring buffers to\n"
    "   (b * PHYS_MEM) where b is a decimal number between 0.0 and 1.0 and PHYS_MEM\n"
    "   is the available memory; USE b < 0.1 EXCEPT WHEN THERE ARE GIGABYTES OF SPARE\n"
    "   RAM to avoid OS failure due to memory starvation.  When multiple threads are\n"
    "   configured, the output is a *file set*: a directory into which each thread\n"
    "   writes its own file; all packets in a flow are written to the same file.\n"
    "\n"
    "   \"[-f or --fingerprint] f\" writes a JSON record for each fingerprint observed,\n"
    "   which incorporates the flow key and the time of observation, into the file or\n"
    "   file set f.  With [-a or --analysis], fingerprints and destinations are\n"
    "   analyzed and the results are included in the JSON output.\n"
    "\n"
    "   \"[-w or --write] w\" writes packets to the file or file set w, in PCAP format.\n"
    "   With [-s or --select], packets are filtered so that only ones with\n"
    "   fingerprint metadata are written.\n"
    "\n"
    "   \"[r or --read] r\" reads packets from the file or file set r, in PCAP format.\n"
    "   A single worker thread is used to process each input file; if r is a file set\n"
    "   then the output will be a file set as well.  With \"[-m or --multiple] m\", the\n"
    "   input file or file set is read and processed m times in sequence; this is\n"
    "   useful for testing.\n"
    "\n"
    "   \"[-u or --user] u\" sets the UID and GID to those of user u; output file(s)\n"
    "   are owned by this user.  With \"[-l or --limit] l\", each JSON output file has\n"
    "   at most l records; output files are rotated, and filenames include a sequence\n"
    "   number.\n"
    "\n"
    "   [-v or --verbose] writes additional information to the standard output,\n"
    "   including the packet count, byte count, elapsed time and processing rate, as\n"
    "   well as information about threads and files.\n"
    "\n"
    "   [-h or --help] writes this extended help message to stdout.\n"
    "\n"
    "EXAMPLES\n"
    "   mercury -c eth0 -w foo.pcap           # capture from eth0, write to foo.pcap\n"
    "   mercury -c eth0 -w foo.pcap -t cpu    # as above, with one thread per CPU\n"
    "   mercury -c eth0 -w foo.mcap -t cpu -s # as above, selecting packet metadata\n"
    "   mercury -r foo.mcap -f foo.json       # read foo.mcap, write fingerprints\n"
    "   mercury -r foo.mcap -f foo.json -a    # as above, with fingerprint analysis\n"
    "   mercury -c eth0 -t cpu -f foo.json -a # capture and analyze fingerprints\n";


enum extended_help {
    extended_help_off = 0,
    extended_help_on  = 1
};

void usage(const char *progname, const char *err_string, enum extended_help extended_help) {
    if (err_string) {
	printf("error: %s\n", err_string);
    }
    printf(mercury_help, progname);
    if (extended_help) {
	printf("%s", mercury_extended_help);
    }
    exit(EXIT_ERR);
}

int main(int argc, char *argv[]) {
    enum status status;
    struct mercury_config cfg = mercury_config_init();
    int c;

    while(1) {
	int opt_idx = 0;
	static struct option long_opts[] = {
	    { "read",        required_argument, NULL, 'r' },
	    { "write",       required_argument, NULL, 'w' },
	    { "capture",     required_argument, NULL, 'c' },
	    { "fingerprint", required_argument, NULL, 'f' },
	    { "analysis",    no_argument,       NULL, 'a' },
	    { "threads",     required_argument, NULL, 't' },
	    { "buffer",      required_argument, NULL, 'b' },
	    { "limit",       required_argument, NULL, 'l' },
	    { "user",        required_argument, NULL, 'u' },
	    { "multiple",    required_argument, NULL, 'm' },
	    { "help",        no_argument,       NULL, 'h' },
	    { "select",      optional_argument, NULL, 's' },
	    { "verbose",     no_argument,       NULL, 'v' },
	    { NULL,          0,                 0,     0  }
	};
	c = getopt_long(argc, argv, "r:w:c:f:t:b:l:u:s::oham:v", long_opts, &opt_idx);
	if (c < 0) {
	    break;
	}
	switch(c) {
	case 'r':
	    if (optarg) {
		cfg.read_filename = optarg;
	    } else {
		usage(argv[0], "error: option r or read requires filename argument", extended_help_off);
	    }
	    break;
	case 'w':
	    if (optarg) {
		cfg.write_filename = optarg;
	    } else {
		usage(argv[0], "error: option w or write requires filename argument", extended_help_off);
	    }
	    break;
	case 'c':
	    if (optarg) {
		cfg.capture_interface = optarg;
	    } else {
		usage(argv[0], "error: option c or capture requires interface argument", extended_help_off);
	    }
	    break;
	case 'f':
	    if (optarg) {
		cfg.fingerprint_filename = optarg;
	    } else {
		usage(argv[0], "error: option f or fingerprint requires filename argument", extended_help_off);
	    }
	    break;
	case 'a':
	    if (optarg) {
		usage(argv[0], "error: option a or analysis does not use an argument", extended_help_off);
	    } else {
		if (analysis_init() == -1) {
		    return EXIT_FAILURE;  /* analysis engine could not be initialized */
		};
		cfg.analysis = analysis_on;
	    }
	    break;
	case 'o':
	    if (optarg) {
		usage(argv[0], "error: option o or overwrite does not use an argument", extended_help_off);
	    } else {
		/*
		 * remove 'exclusive' and add 'truncate' flags, to cause file writes to overwrite files if need be
		 */
		cfg.flags = FLAGS_CLOBBER;
		/*
		 * set file mode similarly
		 */
		cfg.mode = (char *)"w";
	    }
	    break;
	case 's':
	    if (optarg) {
		if (optarg[0] != '=' || optarg[1] == 0) {
		    usage(argv[0], "error: option s or select has the form s=\"packet filter config string\"", extended_help_off);
		}
		cfg.packet_filter_cfg = optarg+1;
	    } 
	    cfg.filter = 1;
	    break;
	case 'h':
	    if (optarg) {
		usage(argv[0], "error: option h or help does not use an argument", extended_help_on);
	    } else {
		printf("mercury: packet metadata capture and analysis\n"); 
		usage(argv[0], NULL, extended_help_on);
	    }
	    break;
	case 't':
	    if (optarg) {
		if (strcmp(optarg, "cpu") == 0) {
		    cfg.num_threads = -1; /* create as many threads as there are cpus */
		    break;
		}
		errno = 0;
		cfg.num_threads = strtol(optarg, NULL, 10);
		if (errno) {
		    printf("%s: could not convert argument \"%s\" to a number\n", strerror(errno), optarg);
		}
	    } else {
		usage(argv[0], "error: option t or threads requires a numeric argument", extended_help_off);
	    }
	    break;
	case 'l':
	    if (optarg) {
		errno = 0;
		cfg.rotate = strtol(optarg, NULL, 10);
		if (errno) {
		    printf("%s: could not convert argument \"%s\" to a number\n", strerror(errno), optarg);
		}
	    } else {
		usage(argv[0], "error: option l or limit requires a numeric argument", extended_help_off);
	    }
	    break;
	case 'p':
	    if (optarg) {
		errno = 0;
		cfg.loop_count = strtol(optarg, NULL, 10);
		if (errno) {
		    printf("%s: could not convert argument \"%s\" to a number\n", strerror(errno), optarg);
		}
	    } else {
		usage(argv[0], "error: option p or loop requires a numeric argument", extended_help_off);
	    }
	    break;
	case 'u':
	    if (optarg) {
		errno = 0;
		cfg.user = optarg;
	    } else {
		usage(argv[0], "error: option u or user requires an argument", extended_help_off);
	    }
	    break;
	case 'b':
	    if (optarg) {
		errno = 0;
		cfg.buffer_fraction = strtof(optarg, NULL);
		if (errno) {
		    printf("%s: could not convert argument \"%s\" to a number\n", strerror(errno), optarg);
		    usage(argv[0], NULL, extended_help_off);
		}
		if (cfg.buffer_fraction < 0.0 || cfg.buffer_fraction > 1.0 ) {
		    usage(argv[0], "buffer fraction must be between 0.0 and 1.0 inclusive", extended_help_off);
		}
	    } else {
		usage(argv[0], "option b or buffer requires a numeric argument", extended_help_off);
	    }
	    break;
	case 'v':
	    if (optarg) {
		usage(argv[0], "error: option v or verbose does not use an argument", extended_help_off);
	    } else {
		cfg.verbosity = 1;
	    }
	    break;
	case '?':
	default:
	    usage(argv[0], NULL, extended_help_off);
	}
    }

    if (!cfg.capture_interface && !cfg.read_filename) {
	usage(argv[0], "neither read [r] nor capture [c] specified on command line", extended_help_off);
    }
    if (cfg.capture_interface && cfg.read_filename) {
	usage(argv[0], "both read [r] and capture [c] specified on command line", extended_help_off);
    }
    if (cfg.fingerprint_filename && cfg.write_filename) {
	usage(argv[0], "both fingerprint [f] and write [w] specified on command line", extended_help_off);
    }

	/*
	 * loop_count < 1  ==> not valid
	 * loop_count > 1  ==> looping (i.e. repeating read file) will be done
	 * loop_count == 1 ==> default condition
	 */
	if (cfg.loop_count < 1) {
		usage(argv[0], "Invalid loop count, it should be >= 1", extended_help_off);
	} else if (cfg.loop_count > 1) {
		printf("Loop count: %d\n", cfg.loop_count);
	}
	
    /*
     * set up signal handlers, so that output is flushed upon close
     */
    signal(SIGINT, sig_close);     /* Ctl-C causes graceful shutdown */
    signal(SIGTERM, sig_close);

    /* process packets */
    if (0) { // was: (num_threads == 1)
	if (cfg.capture_interface) {
	    struct thread_context tc;
	    
	    status = thread_context_init_from_config(&tc, &cfg, 0, NULL);
	    if (status) {
		printf("error: could not initialize thread context\n");
		exit(255);
	    }
	    packet_processing_thread_func(&tc);
	} else if (cfg.read_filename) {
	    printf("TBD\n");
	}
    } else {

#ifndef USE_FANOUT
#warning "TPACKET V3 unavailable; compiling for single-threaded use only"
	printf("error: multithreading not available; the --thread option must be omitted\n");
#endif

	int num_cpus = get_nprocs();  // would get_nprocs_conf() be more appropriate?
	if (cfg.num_threads == -1) {
	    cfg.num_threads = num_cpus;
	    printf("found %d CPU(s), creating %d thread(s)\n", num_cpus, cfg.num_threads);
	}
	
	if (0 && cfg.num_threads > 1) {
	    
	    /*
	     * create subdirectory into which each thread will write its output
	     */
	    char *outdir = cfg.fingerprint_filename ? cfg.fingerprint_filename : cfg.write_filename;
	    create_subdirectory(outdir, create_subdir_mode_do_not_overwrite);
	}
	
	if (cfg.capture_interface) {
	    struct ring_limits rl;
	    
	    ring_limits_init(&rl, cfg.buffer_fraction);

	    af_packet_bind_and_dispatch(&cfg, &rl);
	    
	}

	if (cfg.read_filename) {

	    open_and_dispatch(&cfg);
	    
	}

    }

    analysis_finalize();
    
    return 0;
}
