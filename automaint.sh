#!/bin/sh

set -e

NOCONFIGURE=1 ./autogen.sh

ARGS="--enable-strict --enable-debug"
CROSS="x86_64-w64-mingw32"

configure()
(
	build=$1
	shift

	pwd=$(pwd)
	mkdir -p $build
	cd $build
	echo "Configuring for: $build" >&2
	echo $pwd/configure "$@" >&2
	$pwd/configure "$@"
)

# Configure the local build. To control which arguments are used create a
# CONFIG_SITE script as directed in the autoconf documentation:
# http://www.gnu.org/software/autoconf/manual/autoconf.html#Site-Defaults
configure ./build --prefix=/usr --enable-doc --enable-coverage $ARGS "$@"

# Configure the cross builds
for cross in $CROSS; do
	configure ./$cross --prefix=/opt/$cross --host=$cross $ARGS "$@"
done

# B

(
	echo "CROSS = $CROSS"

	for target in all check clean distclean; do
		echo "$target:"
		echo '	$(MAKE) -C ./build' $target
		echo '	@for dir in $(CROSS); do \'
		echo '		$(MAKE) -C ./$$dir' $target '; \'
		echo '	done'
	done

	for target in distcheck memcheck leakcheck hellcheck install upload-coverage \
		coverage upload-doc upload-release transifex; do
		echo "$target:"
		echo '	$(MAKE) -C ./build' $target
	done

) > ./makefile
