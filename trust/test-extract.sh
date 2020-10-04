#!/bin/sh

. "${builddir=.}/test-init.sh"

teardown()
{
	for x in $TD; do
		if [ -d $x ]; then
			rmdir $x
		elif [ -f $x ]; then
			rm $x
		fi
	done
	TD=""
}

openssl_quiet()
(
	command='/Generating a|-----|^[.+]+$|writing new private key/d'
	exec 3>&1
	openssl $@ 2>&1 >&3 3>&- | sed -r "$command" 3>&-
)

setup()
{
	# Parse the trust paths
	oldifs="$IFS"
	IFS=:
	set $with_trust_paths
	IFS="$oldifs"

	if [ ! -d $1 ]; then
		skip "$1 is not a directory"
		return
	fi

	SOURCE_1=$1
	if [ $# -lt 2 ]; then
		warning "certain tests neutered if only 1 trust path: $with_trust_paths"
		SOURCE_2=$1
	else
		SOURCE_2=$2
	fi

	# Make a temporary directory
	dir=$(mktemp -d)
	cd $dir
	CLEANUP="$dir $TD"

	# Generate a unique identifier
	CERT_1_CN=test_$(dd if=/dev/urandom count=40 bs=1 status=none | base64 | tr -d '+/=')
	CERT_2_CN=test_$(dd if=/dev/urandom count=40 bs=1 status=none | base64 | tr -d '+/=')
	CERT_3_CN=test_$(dd if=/dev/urandom count=40 bs=1 status=none | base64 | tr -d '+/=')

	# Generate relevant certificates
	openssl_quiet req -x509 -newkey rsa:512 -keyout /dev/null -days 3 -nodes \
		-out cert_1.pem -subj /CN=$CERT_1_CN
	openssl_quiet req -x509 -newkey rsa:512 -keyout /dev/null -days 3 -nodes \
		-out cert_2.pem -subj /CN=$CERT_2_CN
	openssl_quiet req -x509 -newkey rsa:512 -keyout /dev/null -days 3 -nodes \
		-out cert_3.pem -subj /CN=$CERT_3_CN

	TD="cert_1.pem cert_2.pem cert_3.pem $TD"

	mkdir -p $SOURCE_1/anchors
	cp cert_1.pem $SOURCE_1/anchors/

	mkdir -p $SOURCE_2/anchors
	cp cert_2.pem $SOURCE_2/anchors/
	cp cert_3.pem $SOURCE_2/anchors/

	TD="$SOURCE_1/anchors/cert_1.pem $SOURCE_2/anchors/cert_2.pem $SOURCE_2/anchors/cert_3.pem $TD"
}

test_extract()
{
	trust extract --filter=ca-anchors --format=pem-bundle \
		--purpose=server-auth --comment \
		extract-test.pem

	assert_contains extract-test.pem $CERT_1_CN
	assert_contains extract-test.pem $CERT_2_CN
	assert_contains extract-test.pem $CERT_3_CN
}

test_blocklist()
{
	mkdir -p $SOURCE_1/blocklist
	cp cert_3.pem $SOURCE_1/blocklist
	TD="$SOURCE_1/blocklist/cert_3.pem $TD"

	trust extract --filter=ca-anchors --format=pem-bundle \
		--purpose=server-auth --comment \
		blocklist-test.pem

	assert_contains blocklist-test.pem $CERT_1_CN
	assert_not_contains blocklist-test.pem $CERT_3_CN
}

run test_extract test_blocklist
