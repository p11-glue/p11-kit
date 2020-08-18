project('p11-kit', 'c',
        version: '0.23.21',
        meson_version: '>= 0.49')

version_arr = meson.project_version().split('.')
major_version = version_arr[0].to_int()
minor_version = version_arr[1].to_int()
micro_version = version_arr[2].to_int()

cc = meson.get_compiler('c')

current = 3
revision = 0
age = 3

soversion = current - age
library_version = '@0@.@1@.@2@'.format(soversion, age, revision)

configinc = include_directories('.')
commoninc = include_directories('common')
p11kitinc = include_directories('p11-kit')
trustinc = include_directories('trust')

add_project_arguments(['-D_GNU_SOURCE', '-DP11_KIT_FUTURE_UNSTABLE_API'],
                      language: 'c')

conf = configuration_data()

conf.set('PACKAGE_MAJOR', major_version)
conf.set('PACKAGE_MINOR', minor_version)

host_system = host_machine.system()
conf.set(host_system == 'windows' ? 'OS_WIN32' : 'OS_UNIX', 1)

if host_system == 'windows'
  shlext = '.dll'
  exeext = '.exe'
else
  shlext = '.so'
  exeext = ''
endif

conf.set_quoted('SHLEXT', shlext)
conf.set_quoted('EXEEXT', exeext)

if host_machine.endian() == 'big'
  conf.set('WORDS_BIGENDIAN', 1)
endif

if get_option('debug')
  conf.set('WITH_DEBUG', 1)
  conf.set('_DEBUG', 1)
endif

conf.set10('WITH_STRICT', get_option('strict'))

prefix = get_option('prefix')
datadir = get_option('datadir')
bindir = get_option('bindir')
libdir = get_option('libdir')
libexecdir = get_option('libexecdir')
sysconfdir = get_option('sysconfdir')
mandir = get_option('mandir')
pkgdatadir = datadir / meson.project_name()
privatedir = libexecdir / meson.project_name()

common_c_args = [
  '-DBINDIR="@0@"'.format(prefix / bindir),
  '-DPRIVATEDIR="@0@"'.format(prefix / privatedir),
  '-DSYSCONFDIR="@0@"'.format(prefix / sysconfdir)
]

top_source_dir = meson.current_source_dir()
top_build_dir = meson.current_build_dir()

tests_c_args = [
  '-DSRCDIR="@0@"'.format(top_source_dir),
  '-DBUILDDIR="@0@"'.format(top_build_dir)
]

conf.set('SIZEOF_UNSIGNED_LONG', cc.sizeof('unsigned long'))

nanosleep_deps = []
dlopen_deps = []
socket_deps = []
thread_deps = []

if host_system != 'windows'
  thread_deps += dependency('threads')
  if not cc.has_function('pthread_create', dependencies: thread_deps)
    error('could not find pthread_create')
  endif

  if not cc.has_function('nanosleep')
    librt = cc.find_library('rt', required: false)
    if cc.has_function('nanosleep', dependencies: librt)
      nanosleep_deps += librt
    else
      error('could not find nanosleep')
    endif
  endif

  if not cc.has_function('dlopen')
    libdl = cc.find_library('dl', required: false)
    if cc.has_function('dlopen', dependencies: libdl)
      dlopen_deps += libdl
    else
      error('could not find dlopen')
    endif
  endif

  # for Solaris we need -lsocket -lnsl for socket stuff, gethostbyname
  # is just a dummy to find -lnsl
  libnsl = cc.find_library('nsl', required: false)
  if libnsl.found()
    if cc.has_function('gethostbyname', dependencies: libnsl)
      socket_deps += libnsl
    endif

    libsocket = cc.find_library('socket', required: false)
    if libsocket.found()
      if cc.has_function('connect', dependencies: [libsocket, libnsl])
        socket_deps += libsocket
      else
        error('could not find socket')
      endif
    endif
  endif

  if cc.has_header('locale.h')
    conf.set('HAVE_LOCALE_H', 1)
    if cc.has_type('locale_t', prefix: '#include <locale.h>')
      conf.set('HAVE_LOCALE_T', 1)
      if cc.has_function('newlocale', prefix: '#include <locale.h>')
        conf.set('HAVE_NEWLOCALE', 1)
      endif
      if cc.has_function('strerror_l', prefix: '#include <string.h>')
        conf.set('HAVE_STRERROR_L', 1)
      endif
    endif
  endif

  # These are things we can work around
  headers = [
    'sys/resource.h',
    'ucred.h'
  ]

  foreach h : headers
    if cc.has_header(h)
      conf.set('HAVE_' + h.underscorify().to_upper(), 1)
    endif
  endforeach

  functions = [
    'fdwalk',
    'getauxval',
    'getexecname',
    'getpeereid',
    'getpeerucred',
    'getprogname',
    'getresuid',
    'issetugid',
    'mkdtemp',
    'mkstemp',
    'secure_getenv',
    'strndup'
  ]

  foreach f : functions
    if cc.has_function(f)
      conf.set('HAVE_' + f.underscorify().to_upper(), 1)
    endif
  endforeach

  if cc.has_member('struct dirent', 'd_type', prefix: '#include <dirent.h>')
    conf.set('HAVE_STRUCT_DIRENT_D_TYPE', 1)
  endif

  tls_test_code_template = '''
#include <stdlib.h>
int main (void) {
static @0@ foo;
return 0;
}
'''
  foreach keyword : ['_Thread_local', '__thread']
    if cc.compiles(tls_test_code_template.format(keyword),
                   name: 'thread-local storage class')
      conf.set('P11_TLS_KEYWORD', keyword)
      break
    endif
  endforeach

  if cc.has_function('gmtime_r')
    conf.set('HAVE_GMTIME_R', 1)
  else
    error('could not find required gmtime_r() function')
  endif

  # Check if these are declared and/or available to link against
  program_invocation_short_name_test_code = '''
#define _GNU_SOURCE
#include <errno.h>
int main (void) { program_invocation_short_name = "test"; }
'''
  if cc.links(program_invocation_short_name_test_code,
              name: 'program_invocation_short_name_test_code')
    conf.set('HAVE_PROGRAM_INVOCATION_SHORT_NAME', 1)
  else
    __progname_test_code = '''
extern char *__progname;
int main (void) { __progname = (char*)0; return 0; }
'''
    if cc.links(__progname_test_code, name: '__progname')
      conf.set('HAVE___PROGNAME', 1)
    endif
  endif

  __libc_enable_secure_test_code = '''
extern int __libc_enable_secure;
int main (void) { __libc_enable_secure = 0; return 0; }
'''
  if cc.links(__libc_enable_secure_test_code, name: '__libc_enable_secure')
    conf.set('HAVE___LIBC_ENABLE_SECURE', 1)
  endif

  vsock_availability_test_code = '''
#include <sys/socket.h>
#include <linux/vm_sockets.h>
struct sockaddr_vm sa = { .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_ANY };
'''
  if cc.compiles(vsock_availability_test_code, name: 'vsock_test')
    conf.set('HAVE_VSOCK', 1)
  endif

  foreach h : ['sys/types.h', 'signal.h']
    foreach t : ['sighandler_t', 'sig_t', '__sighandler_t']
      if cc.has_type(t, prefix: '#include <@0@>'.format(h))
        define = 'HAVE_' + t.underscorify().to_upper()
        conf.set(define, 1)
      endif
    endforeach
  endforeach
endif

headers = [
  'stdbool.h',
]

foreach h : headers
  if cc.has_header(h)
    conf.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

functions = [
  'asprintf',
  'basename',
  'memdup',
  'reallocarray',
  'secure_getenv',
  'setenv',
  'strerror_r',
  'strnstr',
  'vasprintf'
]

foreach f : functions
  if cc.has_function(f)
    conf.set('HAVE_' + f.underscorify().to_upper(), 1)
  endif
endforeach

conf.set10('HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME',
           cc.has_header_symbol('errno.h',
                                'program_invocation_short_name',
                                prefix: '#define _GNU_SOURCE'))

conf.set10('HAVE_DECL_ASPRINTF',
           cc.has_header_symbol('stdio.h', 'asprintf',
                                prefix: '#define _GNU_SOURCE'))

conf.set10('HAVE_DECL_VASPRINTF',
           cc.has_header_symbol('stdio.h', 'vasprintf',
                                prefix: '#define _GNU_SOURCE'))

conf.set10('HAVE_DECL_REALLOCARRAY',
           cc.has_header_symbol('stdlib.h', 'reallocarray'))

# --------------------------------------------------------------------
# libffi

libffi_deps = []
libffi = dependency('libffi', version: '>= 3.0.0', required: get_option('libffi'))
if libffi.found()
  conf.set('WITH_FFI', 1)
  libffi_deps += libffi
endif

closures = get_option('closures')
if closures < 1
  error('at least one closure must be compiled in')
endif

conf.set('P11_VIRTUAL_MAX_FIXED', closures)

# ------------------------------------------------------------------------------
# PKCS#11 Directories

p11_package_config_modules = get_option('module_config')
if p11_package_config_modules == ''
  p11_package_config_modules = pkgdatadir / 'modules'
endif

p11_system_config = get_option('system_config')
if p11_system_config == ''
  p11_system_config = sysconfdir / 'pkcs11'
endif

p11_user_config = get_option('user_config')
p11_module_path = get_option('module_path')
if p11_module_path == ''
  p11_module_path = libdir / 'pkcs11'
endif

p11_system_config_file = p11_system_config / 'pkcs11.conf'
p11_system_config_modules = p11_system_config / 'modules'
p11_user_config_file = p11_user_config / 'pkcs11.conf'
p11_user_config_modules = p11_user_config / 'modules'

# --------------------------------------------------------------------
# Hash implementation

hash_impl = get_option('hash_impl')
if hash_impl == 'freebl'
  libfreebl3 = cc.find_library('freebl3', required: false)
  if libfreebl3.found() and cc.has_function('NSSLOW_Init',
                                            dependencies: libfreebl3)
    conf.set('WITH_FREEBL', 1)
  else
    error('could not find the freebl3 library')
  endif
endif

# --------------------------------------------------------------------
# Trust Module

with_trust_module = false
libtasn1_deps = []
libtasn1 = dependency('libtasn1', version: '>= 2.3',
                      required: get_option('trust_module'))
if libtasn1.found()
  asn1Parser = find_program('asn1Parser', required: get_option('trust_module'))
  if asn1Parser.found()
    conf.set('WITH_ASN1', 1)
    libtasn1_deps += libtasn1
    with_trust_module = true
  endif
endif

trust_paths = get_option('trust_paths')
conf.set_quoted('TRUST_PATHS', trust_paths)

# --------------------------------------------------------------------
# systemd

with_systemd = false
libsystemd_deps = []
libsystemd = dependency('libsystemd', required: get_option('systemd'))
systemd = dependency('systemd', required: get_option('systemd'))
if libsystemd.found() and systemd.found()
  systemduserunitdir = systemd.get_pkgconfig_variable('systemduserunitdir')
  conf.set('WITH_SYSTEMD', 1)
  libsystemd_deps += libsystemd
  with_systemd = true
endif

configure_file(output: 'config.h', configuration: conf)

gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

subdir('common')
subdir('p11-kit')
if with_trust_module
  subdir('trust')
endif
subdir('doc/manual')
if get_option('nls')
  subdir('po')
endif
subdir('bash-completion')
