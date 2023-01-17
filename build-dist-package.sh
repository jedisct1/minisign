#! /bin/sh

tar czpvf minisign-0.11.tar.gz $(git ls-files)
minisign -Sm minisign-0.11.tar.gz

