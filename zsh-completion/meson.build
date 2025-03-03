zshcompdir = get_option('zshcompdir')
if zshcompdir == ''
  zshcompdir = datadir / 'zsh/site-functions'
endif

if not get_option('zsh_completion').disabled()
  install_data('p11-kit.zsh', rename: '_p11-kit', install_dir: zshcompdir)
  if with_trust_module
    install_data('trust.zsh', rename: '_trust', install_dir: zshcompdir)
  endif
endif
