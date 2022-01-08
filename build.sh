#!/bin/bash
VERSION=${VERSION:-`git describe --tags`}

if [ "$VERSION" = "" ]; then
	echo "There are no tag to release version."
	exit 1
fi

mkdir -p dist
rm -f dist/*

platforms=("windows/amd64" "windows/386" "windows/arm64" "linux/amd64" "linux/386" "linux/arm64" "darwin/amd64" "darwin/arm64")

for platform in "${platforms[@]}"
do
	platform_split=(${platform//\// })
	GOOS=${platform_split[0]}
	GOARCH=${platform_split[1]}
	echo CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-w -X main.version=${VERSION}"
	CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-w -X main.version=${VERSION}"
	TARBALL=dist/simpleca-$VERSION-$GOOS-$GOARCH
	if [ "$GOOS" = "windows" ]; then
		zip $TARBALL.zip simpleca.exe
		rm -f simpleca.exe
	else
		tar czf $TARBALL.tar.gz simpleca
		rm -f simpleca
	fi
done
