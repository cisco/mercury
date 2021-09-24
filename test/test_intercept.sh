#!/bin/bash
#
# test_intercept.sh
#
# tests the intercept.so library

retain=0
if [ $# -eq 1 ]; then
    if [ $1 == "--retain" ]; then
        retain=1
    fi
fi

echo "testing intercept.so library for plaintext interception"

# set up shell variables, and change working directory
#
intercept_dir=`pwd`/tmpdir
LD_PRELOAD=`pwd`/../src/intercept.so
mkdir $intercept_dir
echo "using output directory $intercept_dir"
cd $intercept_dir

sites=(accounts.google.com amazon.com apple.com bbc.com bp.blogspot.com cloudflare.com cnn.com creativecommons.org developers.google.com docs.google.com drive.google.com dropbox.com en.wikipedia.org es.wikipedia.org europa.eu facebook.com fr.wikipedia.org github.com google.de googleusercontent.com gstatic.com issuu.com istockphoto.com line.me linkedin.com mail.google.com maps.google.com mozilla.org myspace.com netvibes.com paypal.com play.google.com plus.google.com Root Domain sites.google.com support.google.com t.me uol.com.br vimeo.com vk.com whatsapp.com who.int wordpress.org www.blogger.com www.google.com www.yahoo.com youtu.be youtube.com)

# start interception by exporting variables
#
export intercept_dir
export LD_PRELOAD

# loop over sites
#
echo "looping over all web servers"
blank="                                                       "
for s in ${sites[@]}; do
    echo -ne "visiting $s $blank \r\c" >> /dev/stderr
    wget https://$s >> wget-output.txt 2>&1
    curl --verbose https://$s > $s.curl >> curl-output.txt 2>&1
done
echo "done $blank"

# verify that output JSON file is valid
cat intercept.json | jq . > /dev/null

echo "intercept JSON output is valid"

cd ..

# remove or retain the tmpdir/ directory, based on command line option
#
if [ $retain == "1" ]; then
    echo "retaining files"
else
    rm -rf tmpdir/
fi

# EOF
