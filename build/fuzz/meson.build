if get_option('test')
  fuzz_common_sources = [
    'main.c'
  ]

  fuzzer_target_names = [
    'rpc'
  ]

  fuzzer_targets = []
  foreach target : fuzzer_target_names
    t = executable('@0@_fuzzer'.format(target),
                   ['@0@_fuzzer.c'.format(target)] + fuzz_common_sources,
                   c_args: tests_c_args,
                   include_directories: [configinc, commoninc],
                   link_with: [libp11_kit_testable, libp11_test, libp11_common])
    fuzzer_targets += t
  endforeach

  # Make `ninja fuzz` build all fuzzer targets.
  # This could use alias_target() instead, with a version bump to Meson 0.52.
  run_target('fuzz', depends: fuzzer_targets, command: [ 'true' ])
endif
