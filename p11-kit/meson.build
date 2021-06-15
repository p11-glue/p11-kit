install_headers('deprecated.h',
                'iter.h',
                'p11-kit.h',
                'pin.h',
                'remote.h',
                'uri.h',
                subdir: 'p11-kit-1/p11-kit')

libp11_kit_internal_sources = [
  'conf.c',
  'log.c',
  'filter.c',
  'rpc-transport.c',
  'rpc-message.c',
  'rpc-client.c'
]

libp11_kit_internal_sources += custom_target('generate virtual-fixed-generated.h',
                                             output: 'virtual-fixed-generated.h',
                                             command: [
                                               meson.current_source_dir() / 'gen-virtual-fixed.sh',
                                               '@OUTPUT@', '64'
                                             ])
libp11_kit_internal_sources += 'virtual.c'

libp11_kit_internal_c_args = [
  '-DP11_SYSTEM_CONFIG_FILE="@0@"'.format(prefix / p11_system_config_file),
  '-DP11_SYSTEM_CONFIG_MODULES="@0@"'.format(prefix / p11_system_config_modules),
  '-DP11_PACKAGE_CONFIG_MODULES="@0@"'.format(prefix / p11_package_config_modules),
  '-DP11_USER_CONFIG_FILE="@0@"'.format(p11_user_config_file),
  '-DP11_USER_CONFIG_MODULES="@0@"'.format(p11_user_config_modules),
  '-DP11_MODULE_PATH="@0@"'.format(prefix / p11_module_path)
]

libp11_kit_internal = static_library('p11-kit-internal',
                                     libp11_kit_internal_sources,
                                     dependencies: [libp11_library_dep] + libffi_deps,
                                     c_args: libp11_kit_internal_c_args,
                                     implicit_include_directories: false,
                                     gnu_symbol_visibility: 'hidden')

libp11_kit_sources = [
  'iter.c',
  'messages.c',
  'modules.c',
  'pin.c',
  'proxy.c',
  'proxy-init.c',
  'rpc-server.c',
  'uri.c',
  'util.c'
]

libp11_kit_symbol_map = meson.current_source_dir() / 'libp11-kit.map'
libp11_kit_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,' + libp11_kit_symbol_map
])
libp11_kit_symbol_def = meson.current_source_dir() / 'libp11-kit-@0@.dll.def'.format(soversion)

# Make sure that libp11-kit is unloadable, as it installs
# pthread_atfork to count forks in the ELF constructor.
libp11_kit_ldflags += cc.get_supported_link_arguments([
  '-Wl,-z,nodelete'
])

libp11_kit = shared_library('p11-kit',
                            libp11_kit_sources,
                            install: true,
                            version: library_version,
                            soversion: soversion,
                            dependencies: libffi_deps + dlopen_deps,
                            include_directories: [configinc, commoninc],
                            implicit_include_directories: false,
                            c_args: libp11_kit_internal_c_args,
                            link_args: libp11_kit_ldflags,
                            link_depends: [libp11_kit_symbol_map,
                                           libp11_kit_symbol_def],
                            link_with: libp11_kit_internal,
                            vs_module_defs: libp11_kit_symbol_def)

libp11_kit_dep = declare_dependency(link_with: libp11_kit,
                                    include_directories: [configinc, commoninc])

meson.add_install_script(
  'meson_post_install.sh',
  libdir,
  datadir / 'p11-kit' / 'modules'
)

p11_module_symbol_map = meson.current_source_dir() / 'p11-module.map'
p11_module_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,' + p11_module_symbol_map
])
p11_module_symbol_def = meson.current_source_dir() / 'p11-module.def'

p11v3_module_symbol_map = meson.current_source_dir() / 'p11v3-module.map'
p11v3_module_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,' + p11v3_module_symbol_map
])
p11v3_module_symbol_def = meson.current_source_dir() / 'p11v3-module.def'

if host_system != 'windows'
  shared_module('p11-kit-client',
                'client.c', 'client-init.c',
                name_prefix: '',
                include_directories: [configinc, commoninc],
                dependencies: dlopen_deps,
                link_args: p11v3_module_ldflags,
                link_depends: [p11v3_module_symbol_map,
                               p11v3_module_symbol_def],
                link_with: [libp11_kit_internal],
                vs_module_defs: p11v3_module_symbol_def,
                install: true,
                install_dir: p11_module_path)
endif

if get_option('test')
  fixtures_dir = meson.current_source_dir() / 'fixtures'

  if host_system == 'windows'
    libp11_kit_testable_c_args = [
      '-DP11_SYSTEM_CONFIG_FILE="@0@"'.format(fixtures_dir / 'system-pkcs11.conf'),
      '-DP11_SYSTEM_CONFIG_MODULES="@0@"'.format(fixtures_dir / 'system-modules' / 'win32'),
      '-DP11_PACKAGE_CONFIG_MODULES="@0@"'.format(fixtures_dir / 'package-modules' / 'win32'),
      '-DP11_USER_CONFIG_FILE="@0@"'.format(fixtures_dir / 'user-pkcs11.conf'),
      '-DP11_USER_CONFIG_MODULES="@0@"'.format(fixtures_dir / 'user-modules' / 'win32')
    ]
  else
    libp11_kit_testable_c_args = [
      '-DP11_SYSTEM_CONFIG_FILE="@0@"'.format(fixtures_dir / 'system-pkcs11.conf'),
      '-DP11_SYSTEM_CONFIG_MODULES="@0@"'.format(fixtures_dir / 'system-modules'),
      '-DP11_PACKAGE_CONFIG_MODULES="@0@"'.format(fixtures_dir / 'package-modules'),
      '-DP11_USER_CONFIG_FILE="@0@"'.format(fixtures_dir / 'user-pkcs11.conf'),
      '-DP11_USER_CONFIG_MODULES="@0@"'.format(fixtures_dir / 'user-modules')
    ]
  endif

  libp11_kit_testable_c_args += '-DP11_MODULE_PATH="@0@"'.format(meson.current_build_dir())

  libp11_kit_testable = static_library('p11-kit-testable',
                                       libp11_kit_internal_sources,
                                       libp11_kit_sources,
                                       c_args: libp11_kit_testable_c_args,
                                       implicit_include_directories: false,
                                       dependencies: [libp11_library_dep] + libffi_deps + dlopen_deps)
endif

p11_kit_sources = [
  'lists.c',
  'p11-kit.c',
  'print-config.c'
]

executable('p11-kit',
           p11_kit_sources,
           c_args: common_c_args + libp11_kit_internal_c_args,
           dependencies: [libp11_tool_dep] + libffi_deps + dlopen_deps,
           link_with: [libp11_kit, libp11_kit_internal],
           install: true)

executable('p11-kit-remote',
           'remote.c',
           c_args: common_c_args,
           dependencies: [libp11_tool_dep] + libffi_deps + dlopen_deps,
           link_with: libp11_kit,
           install: true,
           install_dir: prefix / privatedir)

if get_option('test')
  executable('p11-kit-remote-testable',
             'remote.c',
             c_args: common_c_args,
             dependencies: [libp11_tool_dep] + libffi_deps + dlopen_deps,
             link_with: libp11_kit_testable)
endif

executable('p11-kit-server',
           'server.c',
           c_args: common_c_args + [
             '-DP11_KIT_REMOTE="p11-kit-remote"'
           ],
           dependencies: [libp11_tool_dep] + libsystemd_deps + libffi_deps + dlopen_deps,
           implicit_include_directories: false,
           link_with: libp11_kit,
           install: true,
           install_dir: prefix / privatedir)

if get_option('test')
  executable('p11-kit-server-testable',
             'server.c',
             c_args: common_c_args + [
               '-DP11_KIT_REMOTE="p11-kit-remote-testable"'
             ],
             implicit_include_directories: false,
             dependencies: [libp11_tool_dep] + libsystemd_deps + libffi_deps + dlopen_deps,
             link_with: libp11_kit_testable)
endif

if with_systemd
  p11_kit_server_service_conf = configuration_data({
    'bindir': prefix / bindir
  })
  p11_kit_server_service = configure_file(input: 'p11-kit-server.service.in',
                                          output: '@BASENAME@',
                                          configuration: p11_kit_server_service_conf)
  install_data([p11_kit_server_service, 'p11-kit-server.socket'],
               install_dir: systemduserunitdir)
endif

# Check if compilation succeeds with CRYPTOKI_GNU=1

pkcs11_gnu_headers = [
  'iter.h',
  'pin.h',
  'uri.h'
]

gnu_h_gen = generator(find_program('gen-pkcs11-gnu.sh'),
                      output: 'pkcs11-gnu-@BASENAME@.h',
                      arguments: ['@INPUT@', '@OUTPUT@'])

gnu_h = gnu_h_gen.process(pkcs11_gnu_headers)

static_library('p11-kit-pkcs11-gnu',
               gnu_h,
               'pkcs11-gnu.c',
               c_args: [
                 '-DCRYPTOKI_GNU=1', '-DP11_KIT_FUTURE_UNSTABLE_API=1',
               ],
               include_directories: [configinc, commoninc])

# Tests ----------------------------------------------------------------

if get_option('test')
  p11_kit_tests = [
    'test-progname',
    'test-util',
    'test-conf',
    'test-uri',
    'test-pin',
    'test-init',
    'test-modules',
    'test-deprecated',
    'test-proxy',
    'test-iter',
    'test-rpc',
    'test-virtual',
    'test-managed',
    'test-log',
    'test-filter',
    'test-transport'
  ]

  if host_system != 'windows'
    p11_kit_tests += 'test-server'
  endif

  foreach name : p11_kit_tests
    t = executable(name, '@0@.c'.format(name),
                   c_args: tests_c_args + libp11_kit_testable_c_args,
                   include_directories: [configinc, commoninc],
                   dependencies: [libp11_test_dep] + libffi_deps + dlopen_deps,
                   link_with: libp11_kit_testable)
    test(name, t)
  endforeach

  p11_kit_progs = [
    'print-messages',
    'frob-setuid'
  ]

  foreach name : p11_kit_progs
    t = executable(name, '@0@.c'.format(name),
                   c_args: tests_c_args,
                   include_directories: [configinc, commoninc],
                   dependencies: [libp11_test_dep] + libffi_deps + dlopen_deps,
                   link_with: libp11_kit_testable)
  endforeach

  p11_kit_tests_env = environment()
  p11_kit_tests_env.set('abs_top_builddir', top_build_dir)
  p11_kit_tests_env.set('P11_MODULE_PATH', meson.current_build_dir())

  if host_system != 'windows'
    test('test-messages.sh',
         find_program('test-messages.sh'),
         env: p11_kit_tests_env)

    test('test-server.sh',
         find_program('test-server.sh'),
         env: p11_kit_tests_env)
  endif

  mock_sources = {
                   'mock-one': ['mock-module-ep.c'],
                   'mock-two': ['mock-module-ep2.c'],
                   'mock-three': ['mock-module-ep.c'],
                   'mock-four': ['mock-module-ep.c'],
                   'mock-five': ['mock-module-ep3.c'],
                   'mock-seven': ['mock-module-ep5.c'],
                   'mock-eight': ['mock-module-ep6.c'],
                   'mock-nine': ['mock-module-ep7.c'],
                   'mock-ten': ['mock-module-ep8.c']
                 }

  if host_system != 'windows'
    mock_sources += {'mock-six': ['mock-module-ep4.c']}
  endif

  foreach name, sources : mock_sources
    shared_module(name,
                  sources,
                  name_prefix: '',
                  link_args: p11_module_ldflags,
                  link_depends: [p11_module_symbol_map,
                                 p11_module_symbol_def],
                  vs_module_defs: p11_module_symbol_def,
                  dependencies: [libp11_test_dep])
  endforeach
endif

p11_kit_pc_variables = [
  'p11_module_configs=@0@'.format(prefix / p11_package_config_modules),
  'p11_module_path=@0@'.format(prefix / p11_module_path),
  'proxy_module=@0@/p11-kit-proxy.so'.format(prefix / libdir),
  # This is for compatibility. Other packages were using this to determine
  # the directory they should install their module configs to, so override
  # this and redirect them to the new location
  'p11_system_config_modules=@0@'.format(prefix / p11_package_config_modules)
]

if trust_paths != ''
  p11_kit_pc_variables += [
    'p11_trust_paths=@0@'.format(trust_paths)
  ]
endif

pkg.generate(libraries: libp11_kit,
             filebase: 'p11-kit-1',
             name: 'p11-kit',
             description: 'Library and proxy module for properly loading and sharing PKCS#11 modules.',
             subdirs: 'p11-kit-1',
             variables: p11_kit_pc_variables)

pkcs11_conf_example_conf = configuration_data({
  'p11_system_config_file': prefix / p11_system_config_file,
  'p11_user_config': p11_user_config
})
pkcs11_conf_example = configure_file(input: 'pkcs11.conf.example.in',
                                     output: '@BASENAME@',
                                     configuration: pkcs11_conf_example_conf)
install_data(pkcs11_conf_example,
             install_dir: prefix / p11_system_config)
