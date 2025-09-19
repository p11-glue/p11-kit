FROM --platform=linux/amd64 registry.fedoraproject.org/fedora-minimal:42

MAINTAINER Daiki Ueno <ueno@gnu.org>

ARG dnfflags="--setopt install_weak_deps=False"

RUN dnf -y update
RUN dnf -y install 'dnf5-command(builddep)'
RUN dnf -y builddep p11-kit
RUN dnf install $dnfflags -y gettext-devel git libtool make opensc openssl valgrind meson ninja-build bash-completion lcov gcovr python-pip libasan libubsan clang-analyzer mingw64-gcc mingw64-libffi mingw64-libtasn1 wine cppcheck gnutls-utils p11-kit-devel sccache softhsm gtk-doc libxslt xmlto
RUN dnf clean all
