ignore_headers = [
  'private.h',
  'pkcs11.h',
  'conf.h',
  'debug.h',
  'dict.h',
  'filter.h',
  'log.h',
  'mock.h',
  'modules.h',
  'pkcs11.h',
  'pkcs11i.h',
  'pkcs11x.h',
  'private.h',
  'client.h',
  'proxy.h',
  'rpc.h',
  'rpc-message.h',
  'util.h',
  'virtual.h',
  'virtual-fixed.h',
  'array.h',
  'compat.h'
]

content_files = [
  'p11-kit-config.xml',
  'p11-kit-sharing.xml',
  'p11-kit-devel.xml',
  'p11-kit-proxy.xml',
  'p11-kit-trust.xml',
  'p11-kit-remoting.xml',
  'p11-kit.xml',
  'pkcs11.conf.xml',
  'trust.xml',
  'annotation-glossary.xml'
]

configure_file(
  input: 'version.xml.in',
  output: '@BASENAME@',
  configuration: {'VERSION': meson.project_version()})

configure_file(
  input: 'userdir.xml.in',
  output: '@BASENAME@',
  configuration: {'p11_user_config': p11_user_config})

configure_file(
  input: 'sysdir.xml.in',
  output: '@BASENAME@',
  configuration: {'p11_system_config': p11_system_config})

glib_prefix = dependency('glib-2.0').get_pkgconfig_variable('prefix')
fixxref_args = [
  '--html-dir=' + (prefix / gnome.gtkdoc_html_dir(meson.project_name())),
  '--extra-dir=' + (glib_prefix / gnome.gtkdoc_html_dir('glib')),
]

gnome.gtkdoc('p11-kit',
             main_xml: 'p11-kit-docs.xml',
             namespace: 'p11_kit',
             src_dir: 'p11-kit',
             dependencies: libffi_deps + dlopen_deps,
             scan_args: [
               '--ignore-headers=' + ' '.join(ignore_headers),
               '--rebuild-types',
               '--deprecated-guards="P11_KIT_DISABLE_DEPRECATED"'
             ],
             scanobjs_args: [
               '--version'
             ],
             content_files: content_files,
             fixxref_args: fixxref_args,
             install: true)
