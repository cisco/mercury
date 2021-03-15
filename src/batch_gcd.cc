#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <pthread.h>

#include <gmp.h>
#include <gmpxx.h>

#include <map>
#include <vector>
#include <thread>
#include <utility>


/* Number of threads to use. Adjust and recompile if fixed number is desired. */
static const int NTHREADS = std::thread::hardware_concurrency();


struct numlist {
    size_t len;   /* The actual number of elements */
    size_t alloc; /* The number of allocated elements */
    mpz_t *num;
};

struct prodtree {
    size_t height;
    struct numlist **level;
};

struct list_worker_thread {
    struct numlist *d, *s;      /* For the multiplication worker */
    struct numlist *X, *R, *nR; /* For the square/mod worker */
    struct numlist *G, *N;      /* For the divgcd worker */
    int tnum;
    int num_threads;
};


void usage(FILE *fp, const char *progname) {
    fprintf(fp, "Usage: %s < moduli_in_hex.txt\n\n", progname);

    fprintf(fp, "This code efficiently runs all-to-all GCD on RSA moduli.\n");
    fprintf(fp, "The input must be exactly one hex integer per line.\n");
    fprintf(fp, "No blank lines or other characters are permitted.\n\n");

    fprintf(fp, "Informational progress messages are written to stderr.\n");
}


size_t intlog2(size_t num) {

    /* returns the log base-2 value of num rounded up to the nearest int */
    /* 0 -> 0
     * 1 -> 0
     * 2 -> 1
     * 3 -> 2
     * 4 -> 2
     * 5 -> 3
     * 8 -> 3
     * 9 -> 4
     * ...
     */
    size_t l2 = 0;
    for (size_t i = 1; i < num; i *= 2) {
        l2++;
    }

    return l2;
}


struct numlist * makenumlist(size_t len) {
    struct numlist *nlist = (struct numlist *)malloc(sizeof(struct numlist));
    assert(nlist != NULL);
    nlist->len = len;

    if (nlist->len == 0) {
        nlist->alloc = 1;
    } else {
        nlist->alloc = nlist->len;
    }

    nlist->num = (mpz_t *)calloc(sizeof(mpz_t), nlist->alloc);
    assert(nlist->num != NULL);

    for (size_t i = 0; i < nlist->alloc; i++) {
        mpz_init(nlist->num[i]);
    }

    return nlist;
}


/* Equivalent to BSD reallocarray(), which is superior to realloc()
   because it checks for integer overflow in the calculation of the
   value nmemb * size. */
void *realloc_safe(void *ptr, size_t nmemb, size_t size) {
    size_t rsize = nmemb * size;
    if (size != 0 && rsize / size != nmemb) {
        return NULL;   // overflow occurred
    }
    return realloc(ptr, rsize);
}


void grownumlist(struct numlist *nlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);

    nlist->alloc *= 2;
    nlist->num = (mpz_t *)realloc_safe(nlist->num, sizeof(mpz_t), nlist->alloc);
    assert(nlist->num != NULL);

    for (size_t i = nlist->len; i < nlist->alloc; i++) {
        mpz_init(nlist->num[i]);
    }
}


void push_numlist(struct numlist *nlist, mpz_t n) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);

    if (nlist->len >= nlist->alloc) {
        grownumlist(nlist);
    }

    mpz_set(nlist->num[nlist->len], n);
    nlist->len += 1;
}


struct numlist * copynumlist(struct numlist *nlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);

    struct numlist *newlist = makenumlist(nlist->len);

    for (size_t i = 0; i < nlist->len; i++) {
        mpz_set(newlist->num[i], nlist->num[i]);
    }

    return newlist;
}


void freenumlist(struct numlist *nlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);

    for (size_t i = 0; i < nlist->alloc; i++) {
        mpz_clear(nlist->num[i]);
    }

    free(nlist->num);
    free(nlist);
}


void freeprodtree(struct prodtree *ptree) {
    assert(ptree != NULL);
    assert(ptree->level != NULL);

    /* Skips the first level which was just a reference to the
     * initial input list that the product tree was created from
     * in the first place.
     */
    for (size_t l = 1; l < ptree->height; l++) {
        if (ptree->level[l] != NULL) {
            freenumlist(ptree->level[l]);
            ptree->level[l] = NULL;
        }
    }

    free(ptree->level);
    free(ptree);
}


void listmul(struct numlist *d, struct numlist *s) {
    assert(d != NULL);
    assert(d->num != NULL);
    assert(s != NULL);
    assert(s->num != NULL);
    assert(d->len > 0);

    for (size_t i = 0; i < (d->len - 1); i++) {
        mpz_mul(d->num[i], s->num[i * 2], s->num[(i * 2) + 1]);
    }

    /* Either copy or mul the last single / pair */
    if ((s->len & 1) == 0) {
        /* even source len so mul */
        mpz_mul(d->num[d->len - 1], s->num[s->len - 1], s->num[s->len - 2]);
    } else {
        /* odd source len so copy */
        mpz_set(d->num[d->len - 1], s->num[s->len - 1]);
    }
}


void * listmul_worker(void *lwtarg) {

    struct list_worker_thread *lwt = (struct list_worker_thread *)lwtarg;

    for (size_t i = lwt->tnum; i < (lwt->d->len - 1); i += lwt->num_threads) {
        mpz_mul(lwt->d->num[i], lwt->s->num[i * 2], lwt->s->num[(i * 2) + 1]);
    }

    return NULL;
}


void threaded_listmul(struct numlist *d, struct numlist *s, int num_threads) {
    assert(d != NULL);
    assert(d->num != NULL);
    assert(s != NULL);
    assert(s->num != NULL);
    assert(d->len > 0);
    assert(num_threads > 0);

    pthread_t *thread_ids = (pthread_t *)calloc(sizeof(pthread_t), num_threads);
    assert(thread_ids != NULL);
    pthread_attr_t *thread_attrs = (pthread_attr_t *)calloc(sizeof(pthread_attr_t), num_threads);
    assert(thread_attrs != NULL);
    struct list_worker_thread *lwts = (struct list_worker_thread *)calloc(sizeof(struct list_worker_thread), num_threads);
    assert(lwts != NULL);

    int err;
    for (int t = 0; t < num_threads; t++) {
        err = pthread_attr_init(&(thread_attrs[t]));
        if (err) {
            fprintf(stderr, "%s: error initializing attributes for thread %d\n", strerror(err), t);
            exit(255);
        } else {
            /*fprintf(stderr, "Creating multiplication worker thread %d\n", t);*/
        }

        lwts[t].d = d;
        lwts[t].s = s;
        lwts[t].tnum = t;
        lwts[t].num_threads = num_threads;

        err = pthread_create(&(thread_ids[t]), &(thread_attrs[t]), listmul_worker, &(lwts[t]));
        if (err) {
            fprintf(stderr, "%s: error initializing mulworker thread %d\n", strerror(err), t);
            exit(255);
        }
    }


    /* Either copy or mul the last single / pair */
    if ((s->len & 1) == 0) {
        /* even source len so mul */
        mpz_mul(d->num[d->len - 1], s->num[s->len - 1], s->num[s->len - 2]);
    } else {
        /* odd source len so copy */
        mpz_set(d->num[d->len - 1], s->num[s->len - 1]);
    }

    for (int t = 0; t < num_threads; t++) {
        pthread_join(thread_ids[t], NULL);
        if (err) {
            fprintf(stderr, "%s: error joining mulworker thread %d\n", strerror(err), t);
            exit(255);
        }
    }

    free(thread_ids);
    free(thread_attrs);
    free(lwts);
}


void * listsqmod_worker(void *lwtarg) {

    struct list_worker_thread *lwt = (struct list_worker_thread *)lwtarg;

    mpz_t sq;
    mpz_init(sq);
    for (size_t i = lwt->tnum; i < lwt->X->len; i += lwt->num_threads) {
        mpz_mul(sq, lwt->X->num[i], lwt->X->num[i]);
        mpz_mod(lwt->nR->num[i], lwt->R->num[i / 2], sq);
    }
    mpz_clear(sq);

    return NULL;
}


void threaded_listsqmod(struct numlist *X, struct numlist *R, struct numlist *nR, int num_threads) {
    assert(X != NULL);
    assert(X->num != NULL);
    assert(R != NULL);
    assert(R->num != NULL);
    assert(nR != NULL);
    assert(nR->num != NULL);
    assert(num_threads > 0);

    pthread_t *thread_ids = (pthread_t *)calloc(sizeof(pthread_t), num_threads);
    assert(thread_ids != NULL);
    pthread_attr_t *thread_attrs = (pthread_attr_t *)calloc(sizeof(pthread_attr_t), num_threads);
    assert(thread_attrs != NULL);
    struct list_worker_thread *lwts = (struct list_worker_thread *)calloc(sizeof(struct list_worker_thread), num_threads);
    assert(lwts != NULL);

    int err;
    for (int t = 0; t < num_threads; t++) {
        err = pthread_attr_init(&(thread_attrs[t]));
        if (err) {
            fprintf(stderr, "%s: error initializing attributes for sqmod thread %d\n", strerror(err), t);
            exit(255);
        } else {
            /*fprintf(stderr, "Creating multiplication worker thread %d\n", t);*/
        }

        lwts[t].X = X;
        lwts[t].R = R;
        lwts[t].nR = nR;
        lwts[t].tnum = t;
        lwts[t].num_threads = num_threads;

        err = pthread_create(&(thread_ids[t]), &(thread_attrs[t]), listsqmod_worker, &(lwts[t]));
        if (err) {
            fprintf(stderr, "%s: error initializing sqmodworker thread %d\n", strerror(err), t);
            exit(255);
        }
    }

    for (int t = 0; t < num_threads; t++) {
        pthread_join(thread_ids[t], NULL);
        if (err) {
            fprintf(stderr, "%s: error joining sqmodworker thread %d\n", strerror(err), t);
            exit(255);
        }
    }

    free(thread_ids);
    free(thread_attrs);
    free(lwts);
}


void * listdivgcd_worker(void *lwtarg) {

    struct list_worker_thread *lwt = (struct list_worker_thread *)lwtarg;

    mpz_t d;
    mpz_init(d);
    for (size_t i = lwt->tnum; i < lwt->G->len; i += lwt->num_threads) {
        mpz_divexact(d, lwt->R->num[i], lwt->N->num[i]);
        mpz_gcd(lwt->G->num[i], d, lwt->N->num[i]);
    }
    mpz_clear(d);

    return NULL;
}


void threaded_listdivgcd(struct numlist *G, struct numlist *R, struct numlist *N, int num_threads) {
    assert(G != NULL);
    assert(G->num != NULL);
    assert(R != NULL);
    assert(R->num != NULL);
    assert(N != NULL);
    assert(N->num != NULL);
    assert(num_threads > 0);

    pthread_t *thread_ids = (pthread_t *)calloc(sizeof(pthread_t), num_threads);
    assert(thread_ids != NULL);
    pthread_attr_t *thread_attrs = (pthread_attr_t *)calloc(sizeof(pthread_attr_t), num_threads);
    assert(thread_attrs != NULL);
    struct list_worker_thread *lwts = (struct list_worker_thread *)calloc(sizeof(struct list_worker_thread), num_threads);
    assert(lwts != NULL);

    int err;
    for (int t = 0; t < num_threads; t++) {
        err = pthread_attr_init(&(thread_attrs[t]));
        if (err) {
            fprintf(stderr, "%s: error initializing attributes for divgcd thread %d\n", strerror(err), t);
            exit(255);
        } else {
            /*fprintf(stderr, "Creating multiplication worker thread %d\n", t);*/
        }

        lwts[t].G = G;
        lwts[t].R = R;
        lwts[t].N = N;
        lwts[t].tnum = t;
        lwts[t].num_threads = num_threads;

        err = pthread_create(&(thread_ids[t]), &(thread_attrs[t]), listdivgcd_worker, &(lwts[t]));
        if (err) {
            fprintf(stderr, "%s: error initializing divgcdworker thread %d\n", strerror(err), t);
            exit(255);
        }
    }

    for (int t = 0; t < num_threads; t++) {
        pthread_join(thread_ids[t], NULL);
        if (err) {
            fprintf(stderr, "%s: error joining divgcdworker thread %d\n", strerror(err), t);
            exit(255);
        }
    }

    free(thread_ids);
    free(thread_attrs);
    free(lwts);
}


struct prodtree * producttree(struct numlist *nlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);

    struct prodtree *ptree = (struct prodtree *)malloc(sizeof(struct prodtree));
    assert(ptree != NULL);

    ptree->height = intlog2(nlist->len) + 1;
    ptree->level = (struct numlist **)calloc(sizeof(struct numlist *), ptree->height);
    assert(ptree->level != NULL);

    /* The first level of the product tree is the list of integers we
     * were passed in the first place */
    ptree->level[0] = nlist; /*copynumlist(nlist);*/
    for (size_t l = 1; l < ptree->height; l++) {
        ptree->level[l] = makenumlist((ptree->level[l - 1]->len + 1) / 2);
        threaded_listmul(ptree->level[l], ptree->level[l - 1], NTHREADS);
    }

    return ptree;
}

struct numlist * fast_batchgcd(struct numlist *nlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);

    /* def batchgcd_faster(X): */
    /*     prods = producttree(X) */
    /*     R = prods.pop() */
    /*     while prods: */
    /*         X = prods.pop() */
    /*         R = [R[floor(i/2)] % X[i]**2 for i in range(len(X))] */
    /*     return [gcd(r/n,n) for r,n in zip(R,X)] */

    struct prodtree *ptree = producttree(nlist);

    struct numlist *Rlist = ptree->level[ptree->height - 1]; /*copynumlist(ptree->level[ptree->height - 1]);*/
    struct numlist *newRlist;

    /*freenumlist(ptree->level[ptree->height - 1]);
      ptree->level[ptree->height - 1] = NULL;*/

    int needfree = 0;
    for (size_t up = 2; up <= ptree->height; up++) {
        struct numlist *Xlist = ptree->level[ptree->height - up];

        newRlist = makenumlist(Xlist->len);
        threaded_listsqmod(Xlist, Rlist, newRlist, NTHREADS);

        if (up != 2) {
            freenumlist(Rlist);
        }
        Rlist = newRlist;
        needfree = 1;

        /*freenumlist(Xlist);
          ptree->level[ptree->height - up] = NULL;*/
    }

    struct numlist *gcdlist = makenumlist(nlist->len);
    threaded_listdivgcd(gcdlist, Rlist, nlist, NTHREADS);

    if (needfree == 1) {
        freenumlist(Rlist);
    }
    freeprodtree(ptree);

    return gcdlist;
}


/* Note that for a small number of moduli needing additional factoring work
 * this quadratic algorithm is very efficient.
 * For large numbers though it becomes effectively impossible to finish.
 * DJB has a much more complex but much more efficient algorithm
 * when the number of moduli needing co-prime factorization:
 * "Factoring into coprimesin essentially linear time"
 * https://cr.yp.to/lineartime/dcba-20040404.pdf
 */
struct numlist * factor_coprimes(struct numlist *nlist, struct numlist *gcdlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);
    assert(gcdlist != NULL);
    assert(gcdlist->num != NULL);

    /* The smallest co-prime list */
    struct numlist *cplist = makenumlist(nlist->len);

    size_t weak_count = 0; /* A count of the weak moduli */
    uint64_t *weakidx = (uint64_t *)calloc(nlist->len, sizeof(uint64_t));
    assert(weakidx != NULL);

    size_t weak_gcd_count = 0; /* A count of the number of weak moduli needing more GCD work */
    uint64_t *weakidx_gcd = (uint64_t *)calloc(nlist->len, sizeof(uint64_t));
    assert(weakidx_gcd != NULL);

    mpz_t q;
    mpz_init(q);

    /* Each GCD that isn't 1 is vulnerable and needs factoring */
    for (size_t i = 0; i < nlist->len; i++) {
        if (mpz_cmp_ui(gcdlist->num[i], 1) != 0) {
            /* This moduli is weak
             *
             * Case 1: The GCD is less than the moduli meaning
             * we already have factored the moduli. In that case
             * find the smaller of the two co-prime factors and store
             * it in the cplist.
             *
             * Case 2: The GCD is equal to moduli meaning this moduli
             * shares all factors with other moduli and it needs further
             * GCD efforts to separate out the co-primes.
             */

            /* Check case 1 that GCD is already less than moduli */
            if (mpz_cmp(gcdlist->num[i], nlist->num[i]) != 0) {
                /* Store this index */
                weakidx[weak_count] = i;
                weak_count++;

                /* Find the other factor */
                mpz_div(q, nlist->num[i], gcdlist->num[i]);

                /* Set co-prime factor to lesser of the two */
                if (mpz_cmp(gcdlist->num[i], q) < 0) {
                    mpz_set(cplist->num[i], gcdlist->num[i]);
                } else {
                    mpz_set(cplist->num[i], q);
                }
            } else {
                /* We're in case 2 where further GCD work is needed */

                /* Store this index */
                weakidx[weak_count] = i;
                weak_count++;

                /* Also track that we need to do more GCD work */
                weakidx_gcd[weak_gcd_count] = i;
                weak_gcd_count++;
            }

        } else {
            /* The smallest co-prime of a moduli that
             * doesn't share a prime with another moduli
             * is the moduli itself
             */
                mpz_set(cplist->num[i], nlist->num[i]);
        }
    }

    /* Now report on work remaining */
    fprintf(stderr, "Found %lu weak moduli out of %ld.\n", weak_count, nlist->len);
    fprintf(stderr, "%lu weak moduli have both factors shared with others.\n", weak_gcd_count);
    fprintf(stderr, "GCD trials still needed: O(%lu * %lu) == O(%lu)\n", weak_count, weak_gcd_count, weak_count * weak_gcd_count);

    /* To separate out the remaining co-primes we just do trial GCD on the remaining
     * weak moduli until we find a pair that only share one co-prime.
     * This makes the step quadratic in the number of weak moduli
     */
    mpz_t gcd;
    mpz_init(gcd);
    size_t weak_gcd_success = 0;
    for (size_t wgi = 0; wgi < weak_gcd_count; wgi++) {
        for (size_t wi = 0; wi < weak_count; wi++) {

            int idx_w = weakidx[wi];
            int idx_g = weakidx_gcd[wgi];

            /* Skip when these are the same index */
            if (idx_w == idx_g) {
                continue;
            }

            /* GCD this pair */
            mpz_gcd(gcd, nlist->num[idx_w], nlist->num[idx_g]);

            if (mpz_cmp_ui(gcd, 1) != 0) {
                /* Okay they share at least one factor */
                if (mpz_cmp(gcd, nlist->num[idx_g]) != 0) {
                    /* They only shared one factor */
                    mpz_div(q, nlist->num[idx_g], gcd);

                    /* Set co-prime factor to lesser of the two */
                    if (mpz_cmp(gcd, q) < 0) {
                        mpz_set(cplist->num[idx_g], gcd);
                    } else {
                        mpz_set(cplist->num[idx_g], q);
                    }

                    weak_gcd_success++;
                    break;
                }
            }
        }
    }

    fprintf(stderr, "Further found co-factors for %lu weak moduli.\n", weak_gcd_success);

    free(weakidx);
    free(weakidx_gcd);
    mpz_clear(q);
    mpz_clear(gcd);

    return cplist;
}




void print_numlist(struct numlist *nlist) {
    assert(nlist != NULL);
    assert(nlist->num != NULL);
    assert(nlist->len > 0);

    for (size_t i = 0; i < (nlist->len - 1); i++) {
        gmp_fprintf(stderr, "%Zd", nlist->num[i]);
        fprintf(stderr, ", ");
    }
    gmp_fprintf(stderr, "%Zd", nlist->num[nlist->len - 1]);
}


void print_prodtree(struct prodtree *ptree) {
    assert(ptree != NULL);
    assert(ptree->level != NULL);
    assert(ptree->height > 0);

    fprintf(stderr, "[");
    for (size_t i = 0; i < (ptree->height - 1); i++) {
        fprintf(stderr, "[");
        print_numlist(ptree->level[i]);
        fprintf(stderr, "], ");
    }
    fprintf(stderr, "[");
    print_numlist(ptree->level[ptree->height - 1]);
    fprintf(stderr, "]");

    fprintf(stderr, "]\n");
}


/* Check if a line is all hex characters (except trailing newline) */
int is_hex_line(const char *line) {
    int len = strlen(line);
    int len_to_check;
    if (line[len - 1] == '\n') {
        len_to_check = len - 1;
    } else {
        len_to_check = len;
    }
    for (int i = 0; i < len_to_check; i++) {
        if (!isxdigit(line[i])) {
            return 0;
        }
    }
    return 1;
}


int main (int argc, char *argv[]) {

    /* log2 test */
    /*for (size_t n = 0; n < 10; n++) {
     * fprintf(stderr, "intlog2(%ld) = %ld\n", n, intlog2(n));
     * }*/

    /* mpz_t mpz_temp; */
    /* mpz_init(mpz_temp); */

    /* prodtree test */
    /* struct numlist *nlist = makenumlist(0); */
    /* for (int n = 10; n <= 100; n += 10) { */
    /*     mpz_set_ui(mpz_temp, n); */
    /*     push_numlist(nlist, mpz_temp); */
    /* } */
    /* struct prodtree *ptree = producttree(nlist); */
    /* print_prodtree(ptree); */


    /* fast_batchgcd test */
    /* struct numlist *nlist = makenumlist(0); */
    /* for (int n = 1; n <= 50; n++) { */
    /*     mpz_set_ui(mpz_temp, n * 2 + 1); */
    /*     push_numlist(nlist, mpz_temp); */
    /* } */

    /* fprintf(stderr, "["); */
    /* print_numlist(nlist); */
    /* fprintf(stderr, "]\n"); */

    /* struct numlist *gcdlist = fast_batchgcd(nlist); */

    /* fprintf(stderr, "["); */
    /* print_numlist(gcdlist); */
    /* fprintf(stderr, "]\n"); */

    /* mpz_clear(mpz_temp); */
    /* freenumlist(nlist); */
    /* freenumlist(gcdlist); */

    /* This tool takes no arguments. If there are any (e.g., "-h"),
       then print a usage message on stderr and exit. */
    if (argc > 1) {
        usage(stderr, argv[0]);
        exit(-1);
    }

    /* Get ready to read a list of large integers */
    struct numlist *nlist = makenumlist(0);
    mpz_t mpz_temp;
    mpz_init(mpz_temp);

    /* Account for maximum integer size in GMP */
    assert(sizeof(mpz_temp->_mp_size) == sizeof(int));
    const size_t GMP_LIMBS_MAX = INT_MAX;  /* GMP limit */
    size_t estimated_limbs = 0; /* estimate for product of all inputs */

    /* Read lines from stdin where each line is a modulus in hex.
       Record the original line number for each modulus, and detect
       and report duplicates.
     */
    char *linestr = NULL;
    size_t linelen = 0;
    ssize_t read;
    size_t linenum = 1;
    /* Deduplication-related variables */
    std::map<mpz_class, size_t> line_first_seen; // 1st time each modulus appears
    // Due to deduplication, not all lines are fed to batch GCD. Store the
    // original line number for each element i of the batch GCD numlist.
    std::vector<size_t> original_linenum;
    size_t duplicates_ignored = 0;
    while ((read = getline(&linestr, &linelen, stdin)) != -1) {
        if (!is_hex_line(linestr)) {
            fprintf(stderr, "Aborting due to non-hex input on line %zu: %s\n",
                    linenum, linestr);
            exit(2);
        }
        int ret = gmp_sscanf(linestr, "%Zx\n", mpz_temp);
        if (ret == 1) {
            // Ignore this line if it duplicates a previous line.
            mpz_class n(mpz_temp);
            if (line_first_seen.count(n) == 1) {
                fprintf(stdout,
                        "Duplicate ignored: line %zu = line %zu = ",
                        linenum, line_first_seen[n]);
                gmp_fprintf(stdout, "%Zx", n);
                fprintf(stdout, "\n");
                duplicates_ignored++;
            } else {
                // Not a duplicate; add to the list for batch GCD
                line_first_seen[n] = linenum;
                push_numlist(nlist, mpz_temp);
                original_linenum.push_back(linenum);
                estimated_limbs += mpz_temp->_mp_size; /* limbs in product */
            }
        } else {
            fprintf(stderr, "Aborting due to invalid modulus on line %zu: %s\n",
                    linenum, linestr);
            exit(3);
        }
        linenum++;
    }
    if (ferror(stdin)) {
        fprintf(stderr, "Aborting due to error reading line %zu\n", linenum);
        exit(1);
    }
    free(linestr);
    line_first_seen.clear(); // save memory

    /* Abort if the product of all the inputs might exceed GMP's
       largest possible integer.

       GMP max limbs is INT_MAX = 2^31 - 1. On a 64-bit machine, that
       means the length of the maximum integer is approximately
       64*(2^31-1) = 2^37 - 64 bits, or about 16GB.  Therefore, if the
       estimated size of the product of the inputs is greater than
       this limit, we abort without attempting batch GCD.

       Reference: https://gmplib.org/gmp6.0

       "...the mpz code is limited to 2^32 bits on 32-bit hosts and
       2^37 bits on 64-bit hosts."
    */
    if (estimated_limbs > GMP_LIMBS_MAX) {
        fprintf(stderr, "Aborting: product of inputs will exceed GMP max\n");
        fprintf(stderr, "Estimated limbs needed: %zu\n", estimated_limbs);
        fprintf(stderr, "Maximum limbs supported by GMP: %zu\n", GMP_LIMBS_MAX);
        fprintf(stderr, "Where each limb is %zu bytes.\n", sizeof(mp_limb_t));
        exit(4);
    }

    // Print all informational messages to stderr
    fprintf(stderr, "Running batch GCD on %zu moduli", nlist->len);
    if (duplicates_ignored > 0) {
        fprintf(stderr, " (ignoring %zu duplicate line%s)",
                duplicates_ignored,
                duplicates_ignored >= 2 ? "s" : "");
    }
    fprintf(stderr, ".\n");
    fprintf(stderr, "Parallelization: %d threads\n", NTHREADS);

    struct numlist *gcdlist = fast_batchgcd(nlist);

    struct numlist *cplist = factor_coprimes(nlist, gcdlist);

    // Go through the GCD list and look for non-trivial factors.  For
    // each non-trivial factor, record the set of lines sharing that
    // factor.
    std::map<mpz_class,std::vector<size_t>> factor2lines;
    for (size_t i = 0; i < nlist->len; i++) {
        if (mpz_cmp_ui(gcdlist->num[i], 1) != 0) {
            // Get the factors and the original line number
            mpz_class n(nlist->num[i]);
            mpz_class f1(cplist->num[i]);
            mpz_class f2 = n / f1;
            if (f1 > f2) {
                std::swap(f1, f2);
            }
            assert(f1 * f2 == n);
            size_t line = original_linenum[i];

            // Record the factors - lines relationship
            if (factor2lines.count(f1) == 0) {
                factor2lines[f1] = std::vector<size_t>();
            }
            factor2lines[f1].push_back(line);
            if (factor2lines.count(f2) == 0) {
                factor2lines[f2] = std::vector<size_t>();
            }
            factor2lines[f2].push_back(line);

            fprintf(stdout, "Vulnerable modulus on line %zu: ",
                    original_linenum[i]);
            gmp_fprintf(stdout, "%Zx", n);
            fprintf(stdout, " = ");
            gmp_fprintf(stdout, "%Zx", f1);
            fprintf(stdout, " * ");
            gmp_fprintf(stdout, "%Zx", f2);
            fprintf(stdout, "\n");
        }
    }

    // Report which lines share common factors.
    // For example, "1,3;2,4,5;3,6" means the following:
    // - lines 1,3 share a common factor
    // - lines 2,4,5 share a different factor
    // - lines 3,6 share a third factor different from the one shared by 1,3
    fprintf(stderr, "Reporting which lines, if any, share a common factor.\n");
    bool first_factor = true;
    for (const auto& [f, lines]: factor2lines) {
        if (lines.size() > 1) {
            fprintf(stdout, first_factor ? "" : ";");
            for (size_t i = 0; i < lines.size(); i++) {
                fprintf(stdout, "%s%zu", (i==0)?"":",", lines[i]);
            }
            first_factor = false;
        }
    }
    if (!first_factor) { // something was printed
        fprintf(stdout, "\n");
    }

    mpz_clear(mpz_temp);
    freenumlist(nlist);
    freenumlist(gcdlist);
    freenumlist(cplist);

    return 0;
}
