#!/bin/bash

mkdir -p deleteme

# --inet6-only 
wget --user-agent "Mozilla/5.0 (Linux; Android 9; SM-G960F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Mobile Safari/537.36" -nv --directory-prefix=deleteme https://google.com https://facebook.com https://youtube.com https://twitter.com https://microsoft.com https://linkedin.com https://instagram.com https://wikipedia.org https://apple.com https://plus.google.com https://adobe.com https://en.wikipedia.org https://itunes.apple.com https://youtu.be https://vimeo.com https://goo.gl https://wordpress.com https://pinterest.com https://play.google.com https://googletagmanager.com https://maps.google.com https://blogspot.com https://bit.ly https://yahoo.com https://amazon.com https://player.vimeo.com https://wordpress.org https://docs.google.com https://github.com https://godaddy.com https://tumblr.com https://mozilla.org https://flickr.com https://gravatar.com https://parked-content.godaddy.com https://w3.org https://get.adobe.com https://apache.org https://drive.google.com https://sourceforge.net https://nytimes.com https://europa.eu https://support.google.com https://reddit.com https://soundcloud.com https://t.co https://sites.google.com https://amazonaws.com 

# derived from majestic-million.csv
#
# google.com facebook.com youtube.com twitter.com microsoft.com linkedin.com instagram.com wikipedia.org apple.com plus.google.com adobe.com en.wikipedia.org itunes.apple.com youtu.be vimeo.com goo.gl wordpress.com pinterest.com play.google.com googletagmanager.com maps.google.com blogspot.com bit.ly yahoo.com amazon.com player.vimeo.com wordpress.org docs.google.com github.com godaddy.com tumblr.com mozilla.org flickr.com gravatar.com parked-content.godaddy.com w3.org get.adobe.com apache.org drive.google.com sourceforge.net nytimes.com europa.eu support.google.com reddit.com soundcloud.com t.co qq.com sites.google.com amazonaws.com

# rm -rf deleteme

exit 0
