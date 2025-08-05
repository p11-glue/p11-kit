FROM --platform=linux/amd64 registry.fedoraproject.org/fedora-minimal:42

MAINTAINER Daiki Ueno <ueno@gnu.org>

RUN dnf -y update
RUN dnf -y install 'dnf5-command(builddep)'
RUN dnf -y builddep p11-kit
RUN dnf install -y gettext-devel git libtool make opensc openssl valgrind meson ninja-build bash-completion lcov python-pip libasan libubsan clang-analyzer mingw64-gcc mingw64-libffi mingw64-libtasn1 wine cppcheck gnutls-utils p11-kit-devel softhsm
RUN dnf clean all
