if get_option('test')
  fuzz_common_sources = [
    'main.c'
  ]

  fuzzer_target_names = [
    'conf', 'rpc', 'uri',
  ]

  fuzzer_deps = []
  fuzzer_libs = [libp11_kit_testable, libp11_test, libp11_common]
  if with_asn1
    fuzzer_target_names += 'persist'
    fuzzer_libs += [libtrust_testable, libp11_asn1]
    fuzzer_deps += libtasn1_deps
  endif

  fuzzer_targets = []
  foreach target : fuzzer_target_names
    t = executable('@0@_fuzzer'.format(target),
                   ['@0@_fuzzer.c'.format(target)] + fuzz_common_sources,
                   c_args: tests_c_args,
                   include_directories: [configinc, commoninc],
                   dependencies: fuzzer_deps,
                   link_with: fuzzer_libs)
    fuzzer_targets += t
  endforeach

  # Make `ninja fuzz` build all fuzzer targets.
  # This could use alias_target() instead, with a version bump to Meson 0.52.
  run_target('fuzz', depends: fuzzer_targets, command: [ 'true' ])
endif
