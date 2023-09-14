install_headers('pkcs11.h', 'pkcs11x.h', subdir: 'p11-kit-1/p11-kit')

libp11_common_sources = [
  'argv.c',
  'attrs.c',
  'array.c',
  'base64.c',
  'buffer.c',
  'compat.c',
  'constants.c',
  'debug.c',
  'dict.c',
  'hash.c',
  'hex.c',
  'lexer.c',
  'message.c',
  'path.c',
  'pem.c',
  'runtime.c',
  'url.c',
  'vsock.c'
]

libp11_common = static_library('p11-common', libp11_common_sources,
                               gnu_symbol_visibility: 'hidden',
                               include_directories: configinc)

libp11_common_dep = declare_dependency(include_directories: [configinc,
                                                             commoninc],
                                       link_with: libp11_common)

libp11_library = static_library('p11-library', 'library.c',
                                gnu_symbol_visibility: 'hidden',
                                include_directories: configinc)

libp11_library_dep = declare_dependency(link_with: libp11_library,
                                        dependencies: [libp11_common_dep] + thread_deps + libintl_deps)

libp11_library_whole_dep = declare_dependency(link_whole: libp11_library,
                                              dependencies: [libp11_common_dep] + thread_deps + libintl_deps)

if get_option('test')
  libp11_test_sources = [
    'mock.c',
    'test.c'
  ]

  libp11_test = static_library('p11-test', libp11_test_sources,
                               include_directories: configinc)
  libp11_test_dep = declare_dependency(link_with: libp11_test,
                                       dependencies: [libp11_common_dep] + thread_deps)
endif

libp11_tool_sources = [
  'print.c',
  'tool.c'
]

if host_system != 'windows'
  libp11_tool_sources += ['unix-peer.c', 'unix-peer.h']
endif

libp11_tool = static_library('p11-tool', libp11_tool_sources,
                             include_directories: configinc)
libp11_tool_dep = declare_dependency(link_with: libp11_tool,
                                     dependencies: [libp11_common_dep])

# Tests ----------------------------------------------------------------

if get_option('test')
  test_init_conf = configuration_data()
  test_init_conf.set_quoted('prefix', prefix)
  test_init_conf.set_quoted('exec_prefix', prefix)
  test_init_conf.set_quoted('datarootdir', prefix / datadir)
  test_init_conf.set_quoted('datadir', prefix / datadir)
  test_init_conf.set_quoted('sysconfdir', prefix / sysconfdir)
  test_init_conf.set_quoted('libdir', prefix / libdir)
  test_init_conf.set_quoted('libexecdir', prefix / libexecdir)
  test_init_conf.set_quoted('privatedir', prefix / privatedir)
  test_init_conf.set_quoted('with_trust_paths', trust_paths)

  configure_file(
    input: 'test-init.sh.in',
    output: 'test-init.sh',
    configuration: test_init_conf,
  )

  common_tests = [
    'test-tests',
    'test-compat',
    'test-hash',
    'test-dict',
    'test-array',
    'test-constants',
    'test-attrs',
    'test-buffer',
    'test-url',
    'test-path',
    'test-lexer',
    'test-message',
    'test-argv',
    'test-runtime'
  ]

  foreach name : common_tests
    t = executable(name, '@0@.c'.format(name),
                   c_args: tests_c_args,
                   include_directories: configinc,
                   dependencies: dlopen_deps,
                   link_with: [libp11_test, libp11_common])
    test(name, t)
  endforeach

  common_progs = [
    'frob-getauxval',
    'frob-getenv'
  ]

  if host_system != 'windows'
    common_progs += ['frob-getprogname']
  endif

  foreach name : common_progs
    executable(name, '@0@.c'.format(name),
               c_args: tests_c_args,
               include_directories: configinc,
               dependencies: dlopen_deps,
               link_with: [libp11_common])
  endforeach
endif
