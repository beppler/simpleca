#!/bin/bash
VERSION=${VERSION:-`git describe --tags`}

if [ "$VERSION" = "" ]; then
	echo "There are no tag to release version."
	exit 1
fi

mkdir -p dist
rm -f dist/*

for OS in linux windows
do
	for ARCH in amd64 386
	do
		GOOS=$OS GOARCH=$ARCH go build -ldflags "-w -X main.version=${VERSION}"
		TARBALL=dist/simpleca-$VERSION-$OS-$ARCH.tar.gz
		if [ "$OS" = "windows" ]; then
			tar czf $TARBALL simpleca.exe
			rm -f simpleca.exe
		else
			tar czf $TARBALL simpleca
			rm -f simpleca
		fi
	done
done
