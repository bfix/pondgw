#!/bin/bash

PUBN=$(grep "pubN" ../rt/pondgw.conf | sed 's/.*: "\([^"]*\).*/\1/')
PUBG=$(grep "pubG" ../rt/pondgw.conf | sed 's/.*: "\([^"]*\).*/\1/')

sed -e "s/{{.N}}/$PUBN/" -e "s/{{.G}}/$PUBG/" tokenize.tpl > tokenize.go

rm -f tokenize_*
for p in darwin_386 darwin_amd64 linux_386 linux_amd64 windows_386 windows_amd64; do
	. /opt/go/env/$p 
	go build -o tokenize_$p tokenize.go
done

cp tokenize_* tokenize.go ../rt/www/files
