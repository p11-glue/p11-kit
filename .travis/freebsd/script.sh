#!/bin/sh

set -e

meson _build -Dsystemd=disabled -Dbash_completion=disabled
meson test -C _build
