FROM fedora:34

MAINTAINER Daiki Ueno <ueno@gnu.org>

RUN dnf -y update
RUN dnf -y install 'dnf-command(builddep)'
RUN dnf -y builddep 'p11-kit'
RUN dnf install -y gettext-devel git libtool make opensc openssl valgrind meson ninja-build bash-completion lcov python-pip libasan libubsan clang-analyzer mingw64-gcc mingw64-libffi mingw64-libtasn1 wine cppcheck gnutls-utils
RUN dnf clean all
