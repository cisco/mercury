#!/usr/bin/bash
#
# usage: encrypt_file <filename>
#
#    Encrypts <filename> using AES-128-CBC, with an IV computed by
#    encrypting a random none, which prepended to the ciphertext in the
#    output file.  That is, the output file has the following format:
#
#        IV || Enc(K, P_0) || Enc(K, P_1) || ...
#
#    where K is the encryption key, Enc(K, *) is the forward block
#    cipher function, IV = Enc(K, N) where N is a 16-byte nonce
#    selected uniformly at random for each distinct encryption
#    operation, and P_0, P_1 denote successive plaintext blocks.  This
#    is secure and FIPS-140 approved technique (see Appendix C of NIST
#    SP 800-38A).  This file format can be decrypted by applying
#    AES-128-CBC decryption to the file, with the IV set to the
#    all-zero block.  For a summary overview on CBC, see for example
#    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
#
#    Rationale: we want to use the openssl utility to encrypt files,
#    we want the IV to be included in the file so that we don't have
#    to communicate it separately, and we want to use AES-128-CBC
#    without any openssl key-preprocessing steps.

if [ "$#" -ne 2 ]; then
    echo "usage: encrypt_file <filename> <hexkey>"
    echo "   <filename> is the file to be encrypted"

    echo "   <hexkey> is the decryption key; it is a string of 32 random hex characters"
    echo "   generated uniformly at random, e.g. with 'openssl rand -hex 16'"
    exit
fi

# set filename from argument
#
FILE=$1


# verify that file is present and readable
#
if [[ ! -r $FILE ]]; then
    echo "error: could not read file $FILE"
    exit
fi

# set key from argument
#
KEY=$2

# verify that key is well-formed
#
echo "$KEY" | grep "^[0-9a-fA-F]\{32\}$" >/dev/null
retval=$?
if [ "$retval" -ne 0 ]; then
    echo "error: key '$KEY' should be 32 hexadecimal characters"
    exit
fi

# verify that the openssl utility is available
#
if ! command -v openssl > /dev/null 2>&1; then
    echo "error: openssl tool is not available"
    exit
fi

# write random initialization vector (iv) into file
openssl rand 16 > tmpfile

# append plaintext file after iv
cat $FILE >> tmpfile

# encrypt (iv, plaintext) file
openssl enc -aes128 -in tmpfile -out $FILE.enc -nosalt -p -K $KEY -iv 00000000000000000000000000000000 >/dev/null

# cleanup
rm tmpfile

