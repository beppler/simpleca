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
		TARBALL=dist/simpleca-$VERSION-$OS-$ARCH
		if [ "$OS" = "windows" ]; then
			zip $TARBALL.zip simpleca.exe
			rm -f simpleca.exe
		else
			tar czf $TARBALL.tag.gz simpleca
			rm -f simpleca
		fi
	done
done
