#!/bin/sh

docker pull fedora
export CONTAINER=$(docker run -d fedora sleep 1800)

docker exec $CONTAINER dnf -y install 'dnf-command(builddep)'
docker exec $CONTAINER dnf -y builddep p11-kit
docker exec $CONTAINER dnf -y install gettext-devel git libtool make opensc openssl valgrind $EXTRA_PKGS
docker exec $CONTAINER useradd user
