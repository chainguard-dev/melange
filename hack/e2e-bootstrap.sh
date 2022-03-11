#!/bin/sh

# Somebody should rewrite all of this stuff to use Tekton.
# What a disaster.

set -e
set -x

# wtf?
ls -al /dev/null

cat >/etc/apk/repositories <<_EOF_
https://dl-cdn.alpinelinux.org/alpine/edge/main
https://dl-cdn.alpinelinux.org/alpine/edge/community
https://dl-cdn.alpinelinux.org/alpine/edge/testing
_EOF_

apk upgrade -Ua
apk add go cosign build-base git bubblewrap

# stage1 (bootstrap) melange
make melange

# stage2 melange
./melange build --pipeline-dir=pipelines/
mkdir stage2
mv melange*.apk stage2/
apk add --allow-untrusted ./stage2/melange-0.0.1-r0.apk

# stage3 melange
melange build
apk add --allow-untrusted ./melange-0.0.1-r0.apk

# verify melange is working
melange version
