Using a custom fingerprint database with mercury

Mercury's analysis module classifies network sessions, using several
resource files at startup time, including a fingerprint database
(fingerprint_db.json.gz) and a autonomous system number subnet
database (pyasn.db).  These files are installed in
/usr/local/share/mercury by default (and mercury will tell you where
they are installed in the SYSTEM section of 'mercury --help').  The
classifier performs well at the task of analyzing sessions that appear
in its training set, but like any classifier, it might otherwise
perform poorly.  No classifier can identify a process or operating
system that does not appear in its training set.  (Semi-supervised
learning can identify sessions with common attributes, of course, but
that's out of scope here.)  So if you are using mercury's analysis
module, you need to install resource files that are appropriate for
the traffic that you are analyzing, which is especially important for
the fingerprint database, and are up-to-date, which is true for that
file as well as the subnet database.  These instructions tell you how
you can do that.  They assume that you have already installed mercury
on a linux system.

You need to 1) obtain your fingerprint database file, 2) copy that
file into /usr/share/local/mercury, 3) change its owner, group, and
permissions, 4) rename the old fingerprint database to
fingerprint_db.json.gz.old, 5) set a symbolic link from the new file
to fingerprint_db.json.gz, which is the name of the file mercury will
read, and 6) change the owner, group, and permissions of the symbolic
link.  Using a symbolic link makes it easy to change between resource
files; if you don't care about that, you can just copy the new file
over the old one.   Steps 1, 2, 3, 5, and 6 look like this:

```bash
  scp tip-tools-02:/nfs/tip/groups/tip-eta-shared/fingerprints/tls/cisco/mercury/fingerprint-db-recent-proc-family.json.gz .
  sudo cp fingerprint-db-recent-proc-family.json.gz /usr/local/share/mercury/
  sudo chmod +r /usr/local/share/mercury/fingerprint-db-recent-proc-family.json.gz
  sudo chgrp mercury /usr/local/share/mercury/fingerprint-db-recent-proc-family.json.gz
  sudo ln -sf /usr/local/share/mercury/fingerprint-db-recent-proc-family.json.gz /usr/local/share/mercury/fingerprint_db.json.gz
  sudo chgrp -h mercury /usr/local/share/mercury/fingerprint_db.json.gz
  sudo chown -h mercury /usr/local/share/mercury/fingerprint_db.json.gz
```

In the above, we used the ***process family*** database in TIP, which
identifies process families (e.g. Microsoft Office instead of
Powerpoint, Word, etc.), which gives better accuracy and more
intuitive answers.

