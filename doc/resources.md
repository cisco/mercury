# Resource Archives

A mercury resource archive contains data files that mercury can use to analyze network traffic.  It is a POSIX Tape Archive, or `.tar` file.   It may be compressed via GZIP, in which case a `.gz` extension is appended to the `.tar` extension (resulting in a `.tar.gz` extension).  It may be encrypted using the Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC) mode of operation, in which case the initial 16 bytes of the file MUST contain the CBC Initialization Vector (IV), and `.enc` is appended to the extension.  When reading a resource archive, decryption (if any) precedes decompression, and decompression (if any) precedes archive processing.   When writing a resource archive, the order of those operations is reversed.

The following files may appear in a resource archive:

- `VERSION` is a text file containing a single line representing the version of the resource archive, and the type of archive.
    - e.g. `2024-06-26; 2.0.lite`
- `fp_prevalence_tls.txt` is a text file, each line of which is a string representation of a fingerprint.
- `fingerprint_db.json`, `fingerprint_db_normal.json`, and `fingerprint_db_lite.json` are JSON files containing a fingerprint and destination database.
- `doh-watchlist.txt` is a text file, each line of which contains an IPv4 or IPv6 address or a DNS name associated with a DNS over HTTPS server.  DNS names MUST contain punycode representations of internationalized domain names, and not UTF-8.
- `pyasn.db` is a text file, each line of which contains a IP subnet and corresponding decimal Autonomous System Number (ASN), separated by whitespace.

A resource archive MAY contain a `VERSION` file, and MUST contain `fp_prevalence_tls.txt`, `doh-watchlist.txt`, and `pyasn.db` files.  A resource archive MUST contain a `fingerprint_db.json` file, and may contain a `fingerprint_db_lite.json` file.


## Archive content, types and behaviour
- `fingerprint_db.json` and the `VERSION` file contains an identifier including `lite`, e.g. `2.0.lite`:
    1. The archive is a lite archive of the new format.
    2. Classfier ignores the configured `fp_proc_threshold` and `proc_dst_threshold` thresholds and loads the `fingerprint_db.json`
- `fingerprint_db.json` and no identifier in `VERSION`: 
    1. A regular archive of the depricated format.
    2. If `fp_proc_threshold` and `proc_dst_threshold` thresholds are not set, classifier loads the `fingerprint_db.json`
    3. If atleast one of the thresholds, `fp_proc_threshold` and `proc_dst_threshold`, is configured, the classifer does not load and disables all protocols from libmerc config. 
- Dual DB: An archive with both `fingerprint_db.json` and `fingerprint_db_lite.json` and the `VERSION` file contains an identifier including `dual`, e.g. `2.0.dual`:
    1. If atleast one of the thresholds, `fp_proc_threshold` and `proc_dst_threshold`, is configured, the classifier loads `fingerprint_db_lite.json` and ignores the configured thresholds. 
    2. If neither of the thresholds are configured, the classifier loads `fingerprint_db.json`. 
