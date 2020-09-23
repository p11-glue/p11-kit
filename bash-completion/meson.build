bashcompdir = get_option('bashcompdir')
if bashcompdir == ''
  bashcomp = dependency('bash-completion', required: get_option('bash_completion'))
  if bashcomp.found()
    bashcompdir = bashcomp.get_pkgconfig_variable('completionsdir')
  else
    warning('Will not install bash completion due to missing dependencies!')
  endif
endif
if bashcompdir != ''
  install_data('p11-kit', install_dir: bashcompdir)
  if with_trust_module
    install_data('trust', install_dir: bashcompdir)
  endif
endif
