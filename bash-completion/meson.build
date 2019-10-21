bashcomp = dependency('bash-completion', required: false)

if bashcomp.found()
  bashcompdir = bashcomp.get_pkgconfig_variable('completionsdir')
  install_data('p11-kit', install_dir: bashcompdir)
  if with_trust_module
    install_data('trust', install_dir: bashcompdir)
  endif
else
  warning('Will not install bash completion due to missing dependencies!')
endif
