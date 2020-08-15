libtrust_data_sources = [
  'asn1.c',
  'base64.c',
  'pem.c',
  'oid.c',
  'utf8.c',
  'x509.c'
]

basic_asn_h = custom_target('basic.asn.h',
                            output: 'basic.asn.h',
                            input: 'basic.asn',
                            command: [asn1Parser, '-o', '@OUTPUT@', '@INPUT@'])

pkix_asn_h = custom_target('pkix.asn.h',
                           output: 'pkix.asn.h',
                           input: 'pkix.asn',
                           command: [asn1Parser, '-o', '@OUTPUT@', '@INPUT@'])

openssl_asn_h = custom_target('openssl.asn.h',
                            output: 'openssl.asn.h',
                            input: 'openssl.asn',
                            command: [asn1Parser, '-o', '@OUTPUT@', '@INPUT@'])

asn_h_dep = declare_dependency(
  sources: [basic_asn_h, pkix_asn_h, openssl_asn_h]
)

libtrust_data = static_library('libtrust-data',
                               libtrust_data_sources,
                               include_directories: [configinc, commoninc],
                               dependencies: [asn_h_dep] + libtasn1_deps)

libtrust_sources = [
  'builder.c',
  'digest.c',
  'index.c',
  'parser.c',
  'persist.c',
  'module.c',
  'save.c',
  'session.c',
  'token.c'
]

install_data('p11-kit-trust.module',
             install_dir: prefix / p11_package_config_modules)

p11_kit_trust_c_args = [
  '-DP11_DEFAULT_TRUST_PREFIX="@0@"'.format(prefix / datadir),
  '-DP11_SYSTEM_TRUST_PREFIX="@0@"'.format(prefix / sysconfdir)
]

shared_module('p11-kit-trust',
              libtrust_sources,
              'module-init.c',
              name_prefix: '',
              c_args: p11_kit_trust_c_args,
              dependencies: [asn_h_dep, libp11_library_dep] + libtasn1_deps,
              link_args: p11_module_ldflags,
              link_depends: [p11_module_symbol_map,
                             p11_module_symbol_def],
              link_with: libtrust_data,
              vs_module_defs: p11_module_symbol_def,
              install: true,
              install_dir: prefix / p11_module_path)

if get_option('test')
  libtrust_testable_c_args = [
    '-DP11_DEFAULT_TRUST_PREFIX="@0@"'.format(meson.current_build_dir() / 'default'),
    '-DP11_SYSTEM_TRUST_PREFIX="@0@"'.format(meson.current_build_dir() / 'system')
  ]

  libtrust_testable = static_library('libtrust-testable',
                                     libtrust_sources,
                                     include_directories: [configinc, commoninc],
                                     c_args: libtrust_testable_c_args,
                                     dependencies: [asn_h_dep] + libtasn1_deps)
endif

trust_sources = [
  'anchor.c',
  'parser.c',
  'persist.c',
  'digest.c',
  'dump.c',
  'enumerate.c',
  'extract.c',
  'extract-jks.c',
  'extract-edk2.c',
  'extract-openssl.c',
  'extract-pem.c',
  'extract-cer.c',
  'list.c',
  'save.c',
  'trust.c'
]

executable('trust',
           trust_sources,
           c_args: common_c_args,
           link_with: libtrust_data,
           dependencies: [asn_h_dep,
                          libp11_kit_dep,
                          libp11_tool_dep] + libffi_deps + dlopen_deps + libtasn1_deps,
           install: true)

# Tests ----------------------------------------------------------------

if get_option('test')
  libtrust_test_sources = [
    'test-trust.c',
    'digest.c'
  ]

  libtrust_test = static_library('libtrust-test',
                                 libtrust_test_sources,
                                 include_directories: [configinc, commoninc])

  trust_tests = [
    'test-digest',
    'test-asn1',
    'test-base64',
    'test-pem',
    'test-oid',
    'test-utf8',
    'test-x509',
    'test-persist',
    'test-index',
    'test-parser',
    'test-builder',
    'test-token',
    'test-module',
    'test-save',
    'test-enumerate',
    'test-cer',
    'test-bundle',
    'test-openssl',
    'test-edk2',
    'test-jks'
  ]

  foreach name : trust_tests
    t = executable(name, '@0@.c'.format(name),
                   c_args: common_c_args + tests_c_args + libtrust_testable_c_args,
                   dependencies: [asn_h_dep,
                                  libp11_kit_dep,
                                  libp11_library_dep,
                                  libp11_test_dep] + dlopen_deps,
                   link_with: [libtrust_testable, libtrust_data, libtrust_test])
    test(name, t)
  endforeach

  trust_progs = [
    'frob-pow',
    'frob-token',
    'frob-nss-trust',
    'frob-cert',
    'frob-bc',
    'frob-ku',
    'frob-eku',
    'frob-ext',
    'frob-oid'
  ]

  foreach name : trust_progs
    t = executable(name, '@0@.c'.format(name),
                   c_args: tests_c_args,
                   dependencies: [asn_h_dep,
                                  libp11_kit_dep,
                                  libp11_library_dep,
                                  libp11_test_dep] + libffi_deps + dlopen_deps,
                   link_with: [libtrust_testable, libtrust_data, libtrust_test])
  endforeach
endif
