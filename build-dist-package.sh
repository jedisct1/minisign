#! /bin/sh

tar czpvf minisign-0.12.tar.gz $(git ls-files)
minisign -Sm minisign-0.12.tar.gz
