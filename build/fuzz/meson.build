if get_option('test')
  fuzz_common_sources = [
    'main.c'
  ]

  fuzzer_targets = [
    'rpc'
  ]

  foreach target : fuzzer_targets
    executable('@0@_fuzzer'.format(target),
               ['@0@_fuzzer.c'.format(target)] + fuzz_common_sources,
               c_args: tests_c_args,
               include_directories: [configinc, commoninc],
               link_with: [libp11_kit_testable, libp11_test, libp11_common])
  endforeach
endif
