#!/bin/sh

for FILE in "$@"
do
    if [ -e $FILE ];
    then
        echo 'Indenting '${FILE}
        emacs ${FILE} -batch --eval '(setq require-final-newline t)' --eval '(setq python-indent-offset 4)' --eval '(setq c-basic-offset 4)' --eval '(setq tab-width 4)' --eval '(setq indent-tabs-mode nil)' --eval '(delete-trailing-whitespace)' --eval '(indent-region (point-min) (point-max) nil)' --eval '(set-buffer-modified-p t)' -f save-buffer
    else
        echo 'Could not find '${FILE}
    fi
done
