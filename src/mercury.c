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
#include "af_packet_v3.h"
#include "analysis.h"
#include "rnd_pkt_drop.h"
#include "signal_handling.h"
#include "config.h"

struct thread_queues t_queues;
int sig_stop_output = 0; /* Extern defined in mercury.h for global visibility */
int t_output_p = 0;
pthread_cond_t t_output_c  = PTHREAD_COND_INITIALIZER;
pthread_mutex_t t_output_m = PTHREAD_MUTEX_INITIALIZER;


void init_t_queues(int n) {
    t_queues.qnum = n;
    t_queues.queue = (struct ll_queue *)calloc(n, sizeof(struct ll_queue));

    if (t_queues.queue == NULL) {
        fprintf(stderr, "Failed to allocate memory for thread queues\n");
        exit(255);
    }

    for (int i = 0; i < n; i++) {
        t_queues.queue[i].qnum = i; /* only needed for debug output */
        t_queues.queue[i].ridx = 0;
        t_queues.queue[i].widx = 0;

        for (int j = 0; j < LLQ_DEPTH; j++) {
            t_queues.queue[i].msgs[j].used = 0;
        }
    }
}


void destroy_thread_queues() {
    free(t_queues.queue);
    t_queues.queue = NULL;
    t_queues.qnum = 0;
}


int time_less(struct timespec *tsl, struct timespec *tsr) {

    if ((tsl->tv_sec < tsr->tv_sec) || ((tsl->tv_sec == tsr->tv_sec) && (tsl->tv_nsec < tsr->tv_nsec))) {
        return 1;
    } else {
        return 0;
    }
}

int queue_less(int ql, int qr, struct tourn_tree *t_tree) {

    /* returns 1 if the time of ql < qr and 0 otherwise
     * Also sets t_tree->stalled = 1 if needed.
     *
     * WARNING: This function is NOT thread safe!
     *
     * Meaning the access to the 'used' member in the queue
     * struct happens and then later the access to the
     * struct timespec happens.
     * This function must be called by the output thread
     * and ONLY the output thread because if
     * queues are changed while this function is going
     * shit will hit the fan!
     */

    int ql_used = 0;
    int qr_used = 0;

    /* check for a queue stall before we return anything otherwise
     * we could short-circuit logic before realizing one of the
     * queues was stalled
     */
    if ((ql >= 0) && (ql < t_queues.qnum)) {
        ql_used = t_queues.queue[ql].msgs[t_queues.queue[ql].ridx].used;
        if (ql_used == 0) {
            t_tree->stalled = 1;
        }
    }
    if ((qr >= 0) && (qr < t_queues.qnum)) {
        qr_used = t_queues.queue[qr].msgs[t_queues.queue[qr].ridx].used;
        if (qr_used == 0) {
            t_tree->stalled = 1;
        }
    }

    /* If the queue numbers here are -1 that means we've spilled
     * over into the portion of the tournament tree that isn't
     * populated by queues because the number of queues wasn't a
     * power-of-two
     *
     * Don't blindly combine this into the above statements as an else
     * without realising that both qr and ql must be checked for
     * a stall before any return is done
     */
    if (ql == -1) {
        return 0;
    } else if (qr == -1) {
        return 1;
    }

    /* The t_tree is built as though the number of queues is
     * a power-of-two however it doesn't actually have to be
     * that way so if the computed queue number spills over past
     * the actual number of queues we just fill the tree with -1
     * to indicate that portion of the tree shouldn't be use
     * in the tournament (and any real queue compared to a -1 queue
     * automatically "wins".
     */
    if (ql >= t_queues.qnum) {
        return 0;
    } else if (qr >= t_queues.qnum) {
        return 1;
    }

    /* This is where we do the actual less comparison */
    if (ql_used == 0) {
        return 0;
    } else if (qr_used == 0) {
        return 1;
    } else {
        struct timespec *tsl = &(t_queues.queue[ql].msgs[t_queues.queue[ql].ridx].ts);
        struct timespec *tsr = &(t_queues.queue[qr].msgs[t_queues.queue[qr].ridx].ts);

        return time_less(tsl, tsr);
    }
}


int lesser_queue(int ql, int qr, struct tourn_tree *t_tree) {

    if (queue_less(ql, qr, t_tree) == 1) {
        return ql;
    } else {
        return qr;
    }
}


void run_tourn_for_queue(struct tourn_tree *t_tree, int q) {

    /*
     * The leaf index in the tree for a particular queue
     * is the queue's index in the tree minus 1 (or 2) divided by 2
     * however we don't bother to store the bottem-most layer in the
     * the tree and also, by clearing the least significant bit in
     * the q number we can reduce the minus 1 or 2 to just minus 1.
     */

    int ql = (q % 2 == 0)? q : q - 1; // the even q
    int qr = ql + 1;                  // the odd q
    int lidx = ((ql + t_tree->qp2) - 1) / 2;

    t_tree->tree[lidx] = lesser_queue(ql, qr, t_tree);

    /* This "walks" back up the tree to the root node (0) */
    while (lidx > 0) {
        lidx = (lidx - 1) / 2;
        ql = t_tree->tree[(lidx * 2) + 1];
        qr = t_tree->tree[(lidx * 2) + 2];

        t_tree->tree[lidx] = lesser_queue(ql, qr, t_tree);
    }
}


void debug_print_tour_tree(struct tourn_tree *t_tree) {

    fprintf(stderr, "Tourn Tree size: %d\n", (t_tree->qp2 - 1));
    int i = 0;
    int l = 2;
    while (i < (t_tree->qp2 - 1)) {
        for (; i < l - 1; i++) {
            fprintf(stderr, "%d ", t_tree->tree[i]);
        }
        fprintf(stderr, "\n");
        l *= 2;
    }

    fprintf(stderr, "Ready queues:\n");
    for (int q = 0; q < t_tree->qnum; q++) {
        if (t_queues.queue[q].msgs[t_queues.queue[q].ridx].used == 1) {
            fprintf(stderr, "%d ", q);
        }
    }
    fprintf(stderr, "\n");
}



void *output_thread_func(void *arg) {

    (void)arg;

    int err;
    err = pthread_mutex_lock(&t_output_m);
    if (err != 0) {
        fprintf(stderr, "%s: error locking output start mutex for stats thread\n", strerror(err));
        exit(255);
    }
    while (t_output_p != 1) {
        err = pthread_cond_wait(&t_output_c, &t_output_m);
        if (err != 0) {
            fprintf(stderr, "%s: error waiting on output start condition for stats thread\n", strerror(err));
            exit(255);
        }
    }
    err = pthread_mutex_unlock(&t_output_m);
    if (err != 0) {
        fprintf(stderr, "%s: error unlocking output start mutex for stats thread\n", strerror(err));
        exit(255);
    }

    struct tourn_tree t_tree;
    t_tree.qnum = t_queues.qnum;
    t_tree.qp2 = 2; /* This is the smallest power of 2 >= the number of queues */
    while (t_tree.qp2 < t_tree.qnum) {
        t_tree.qp2 *= 2;
    }
    t_tree.tree = (int *)calloc(t_tree.qp2 - 1, sizeof(int)); /* The tournament needs qp2 - 1 nodes */
    if (t_tree.tree == NULL) {
        fprintf(stderr, "Failed to allocate enough memory for the tournament tree\n");
        exit(255);
    }

    int all_output_flushed = 0;
    while (all_output_flushed == 0) {

        /* run the tournament for every queue */
        t_tree.stalled = 0;
        /* Every other works here because the tournament
         * works on pairs: {0,1}, {2,3}, {3,4}, etc.
         * Passing a q from either pair runs the tournament
         * for the pair.
         */
        for (int q = 0; q < t_tree.qp2; q += 2) {
            run_tourn_for_queue(&t_tree, q);
        }

        int wq; /* winning queue */
        while (t_tree.stalled == 0) {
            wq = t_tree.tree[0];

            struct llq_msg *wmsg = &(t_queues.queue[wq].msgs[t_queues.queue[wq].ridx]);
            if (wmsg->used == 1) {
                fwrite(wmsg->buf, wmsg->len, 1, stdout);

                /* A full memory barrier prevents the following flag (un)set from happening too soon */
                __sync_synchronize();
                wmsg->used = 0;

                t_queues.queue[wq].ridx = (t_queues.queue[wq].ridx + 1) % LLQ_DEPTH;

                run_tourn_for_queue(&t_tree, wq);
            }
            else {
                break;
            }

        }

        /* The tree is now stalled because a queue has been emptied
         * Now we must remove messages as long as they are "too old"
         */
        struct timespec old_ts;
        if (clock_gettime(CLOCK_REALTIME, &old_ts) != 0) {
            perror("Unable to get current time");
        }

        /* This is the time we compare against to flush */
        old_ts.tv_sec -= LLQ_MAX_AGE;

        int old_done = 0;
        while (old_done == 0) {
            wq = t_tree.tree[0];

            struct llq_msg *wmsg = &(t_queues.queue[wq].msgs[t_queues.queue[wq].ridx]);
            if (wmsg->used == 0) {
                /* Even the top queue has nothing so we can just stop now */
                old_done = 1;

                /* This is how we detect no more output is coming */
                if (sig_stop_output != 0) {
                    all_output_flushed = 1;
                }

                break;
            } else if (time_less(&(wmsg->ts), &old_ts) == 1) {
                fwrite(wmsg->buf, wmsg->len, 1, stdout);

                /* A full memory barrier prevents the following flag (un)set from happening too soon */
                __sync_synchronize();
                wmsg->used = 0;

                t_queues.queue[wq].ridx = (t_queues.queue[wq].ridx + 1) % LLQ_DEPTH;

                run_tourn_for_queue(&t_tree, wq);
            } else {
                old_done = 1;
            }
        }

        struct timespec sleep_ts;
        sleep_ts.tv_sec = 0;
        sleep_ts.tv_nsec = 1000;
        nanosleep(&sleep_ts, NULL);
    } /* End all_output_flushed == 0 meaning we got a signal to stop */

    return NULL;
}


#define TWO_TO_THE_N(N) (unsigned int)1 << (N)

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

void create_subdirectory(const char *outdir,
                         enum create_subdir_mode mode) {
    printf("creating output directory %s\n", outdir);
    if (mkdir(outdir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
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
    struct pkt_proc *pkt_processor;
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
    enum status status;

    tc->pkt_processor = pkt_proc_new_from_config(cfg, tnum, fileset_id);
    if (tc->pkt_processor == NULL) {
        printf("error: could not initialize frame handler\n");
        return status_err;
    }

    // if cfg->use_test_packet is on, read_filename will be NULL
    if (cfg->read_filename != NULL) {
        status = filename_append(input_filename, cfg->read_filename, "/", fileset_id);
        if (status) {
            return status;
        }
        status = pcap_file_open(&tc->rf, input_filename, io_direction_reader, cfg->flags);
        if (status) {
            printf("%s: could not open pcap input file %s\n", strerror(errno), cfg->read_filename);
            return status;
        }
    }
    return status_ok;
}

void *pcap_file_processing_thread_func(void *userdata) {
    struct pcap_reader_thread_context *tc = (struct pcap_reader_thread_context *)userdata;
    enum status status;

    status = pcap_file_dispatch_pkt_processor(&tc->rf, tc->pkt_processor, tc->loop_count);
    if (status) {
        printf("error in pcap file dispatch (code: %d)\n", (int)status);
        return NULL;
    }

    return NULL;
}

#define BILLION 1000000000L

inline void get_clocktime_before (struct timespec *before) {
    if (clock_gettime(CLOCK_REALTIME, before) != 0) {
        // failed to get clock time, set the uninitialized struct to zero
        bzero(before, sizeof(struct timespec));
        perror("error: could not get clock time before fwrite file header\n");
    }
}

inline uint64_t get_clocktime_after (struct timespec *before,
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
            //        struct pkt_proc_stats pkt_stats = tc[i].pkt_processor->get_stats();
            bytes_written += tc[i].pkt_processor->bytes_written;
            packets_written += tc[i].pkt_processor->packets_written;
            delete tc[i].pkt_processor;
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
        //    struct pkt_proc_stats pkt_stats = tc.pkt_processor->get_stats();
        bytes_written = tc.pkt_processor->bytes_written;
        packets_written = tc.pkt_processor->packets_written;
        pcap_file_close(&(tc.rf));
        delete tc.pkt_processor;
    }

    nano_seconds = get_clocktime_after(&before, &after);
    double byte_rate = ((double)bytes_written * BILLION) / (double)nano_seconds;

    if (cfg->write_filename && cfg->verbosity) {
        printf("For all files, packets written: %" PRIu64 ", bytes written: %" PRIu64 ", nano sec: %" PRIu64 ", bytes per second: %.4e\n",
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
    "   [-d or --directory] d                 # set working directory to d\n"
    "--read OPTIONS\n"
    "   [-m or --multiple] count              # loop over read_file count >= 1 times\n"
    "GENERAL OPTIONS\n"
    "   --config c                            # read configuration from file c\n"
    "   [-a or --analysis]                    # analyze fingerprints\n"
    "   [-s or --select]                      # select only packets with metadata\n"
    "   [-l or --limit] l                     # rotate JSON files after l records\n"
    "   [-v or --verbose]                     # additional information sent to stdout\n"
    "   [-p or --loop] loop_count             # loop count >= 1 for the read_file\n"
    //  "   [--adaptive]                          # adaptively accept or skip packets for pcap file\n"
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
    struct mercury_config cfg = mercury_config_init();
    int c;
    int num_inputs = 0;  // we need to have one and only one input

    while(1) {
        int opt_idx = 0;
        static struct option long_opts[] = {
            { "config",      required_argument, NULL, 1   },
            { "read",        required_argument, NULL, 'r' },
            { "write",       required_argument, NULL, 'w' },
            { "directory",   required_argument, NULL, 'd' },
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
            { "loop",        required_argument, NULL, 'p' },
            { "adaptive",    no_argument,       NULL,  0  },
            { NULL,          0,                 0,     0  }
        };
        c = getopt_long(argc, argv, "r:w:c:f:t:b:l:u:soham:vp:d:", long_opts, &opt_idx);
        if (c < 0) {
            break;
        }
        switch(c) {
        case 1:
            if (optarg) {
                mercury_config_read_from_file(&cfg, optarg);
                num_inputs++;
            } else {
                usage(argv[0], "error: option config requires filename argument", extended_help_off);
            }
            break;
        case 'r':
            if (optarg) {
                cfg.read_filename = optarg;
                num_inputs++;
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
        case 'd':
            if (optarg) {
                cfg.working_dir = optarg;
                num_inputs++;
            } else {
                usage(argv[0], "error: option d or directory requires working directory argument", extended_help_off);
            }
            break;
        case 'c':
            if (optarg) {
                cfg.capture_interface = optarg;
                num_inputs++;
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
        case 'T':
            if (optarg) {
                usage(argv[0], "error: option T or test does not use an argument", extended_help_off);
            } else {
                cfg.use_test_packet = 1;
                num_inputs++;
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
        case 0:
            /* The option --adaptive to adaptively accept or skip packets for PCAP file. */
            if (optarg) {
                usage(argv[0], "error: option --adaptive does not use an argument", extended_help_off);
            } else {
                cfg.adaptive = 1;
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

    if (num_inputs == 0) {
        usage(argv[0], "neither read [r] nor capture [c] specified on command line", extended_help_off);
    }
    if (num_inputs > 1) {
        usage(argv[0], "incompatible arguments read [r] and capture [c] specified on command line", extended_help_off);
    }
    if (cfg.fingerprint_filename && cfg.write_filename) {
        usage(argv[0], "both fingerprint [f] and write [w] specified on command line", extended_help_off);
    }
    if (cfg.num_threads != 1 && cfg.fingerprint_filename == NULL && cfg.write_filename == NULL) {
        usage(argv[0], "multiple threads [t] requested, but neither fingerprint [f] no write [w] specified on command line", extended_help_off);
    }

    if (cfg.analysis) {
        if (analysis_init() == -1) {
            return EXIT_FAILURE;  /* analysis engine could not be initialized */
        };
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

    /* The option --adaptive works only with -w PCAP file option and -c capture interface */
    if (cfg.adaptive > 0) {
        if (cfg.write_filename == NULL || cfg.capture_interface == NULL) {
            usage(argv[0], "The option --adaptive requires options -c capture interface and -w pcap file.", extended_help_off);
        } else {
            set_percent_accept(30); /* set starting percentage */
        }
    }

    /*
     * set up signal handlers, so that output is flushed upon close
     */
    if (setup_signal_handler() != status_ok) {
        fprintf(stderr, "%s: error while setting up signal handlers\n", strerror(errno));
    }

    /* process packets */

    int num_cpus = get_nprocs();  // would get_nprocs_conf() be more appropriate?
    if (cfg.num_threads == -1) {
        cfg.num_threads = num_cpus;
        printf("found %d CPU(s), creating %d thread(s)\n", num_cpus, cfg.num_threads);
    }

    /* make the thread queues */
    init_t_queues(cfg.num_threads);
    pthread_t output_thread;
    int err = pthread_create(&output_thread, NULL, output_thread_func, NULL);
    if (err != 0) {
        perror("error creating output thread");
    }

    /* init random number generator */
    srand(time(0));

    if (cfg.capture_interface) {
        struct ring_limits rl;

        if (cfg.verbosity) {
            printf("initializing interface %s\n", cfg.capture_interface);
        }
        ring_limits_init(&rl, cfg.buffer_fraction);

        af_packet_bind_and_dispatch(&cfg, &rl);

    } else if (cfg.read_filename) {

        open_and_dispatch(&cfg);

    }

    if (cfg.analysis) {
        analysis_finalize();
    }

    fprintf(stderr, "Stopping output thread and flushing queued output to disk.\n");
    sig_stop_output = 1;
    pthread_join(output_thread, NULL);
    destroy_thread_queues();

    return 0;
}
