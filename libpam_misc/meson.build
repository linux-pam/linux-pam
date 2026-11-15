subdir('include/security')

libpam_misc_src = [
  'help_env.c',
  'misc_conv.c',
]

libpam_misc_inc = include_directories('include')

libpam_misc_version = '0.82.1'
libpam_misc_map = 'libpam_misc.map'
libpam_misc_map_path = meson.current_source_dir() / libpam_misc_map

libpam_misc_link_deps = [libpam_misc_map]
libpam_misc_link_args = ['-Wl,--version-script=' + libpam_misc_map_path]

libpam_misc = shared_library(
  'pam_misc',
  sources: libpam_misc_src,
  include_directories: [libpam_misc_inc, libpamc_inc],
  dependencies: [libpam_internal_dep, libpam_dep],
  link_depends: libpam_misc_link_deps,
  link_args: libpam_misc_link_args,
  version: libpam_misc_version,
  install: true,
)

libpam_misc_dep = declare_dependency(
  include_directories: [libpam_misc_inc],
  link_with: [libpam_misc],
)

tst_misc_conv = executable(
  'tst-misc_conv',
  sources: 'tst-misc_conv.c',
  include_directories: [libpamc_inc],
  dependencies: [libpam_dep, libpam_misc_dep],
  c_args: ['-DLIBPAM_COMPILE'],
  link_args: exe_link_args,
)

foreach case: ['arguments', 'null-arguments', 'informational']
  test('misc_conv ' + case, tst_misc_conv, args: [case])
endforeach

foreach echo: ['on', 'off']
  foreach case: ['line', 'empty', 'eof', 'no-newline', 'multiple',
                'below-limit', 'at-limit', 'above-limit']
    test('misc_conv input echo-' + echo + ' ' + case, tst_misc_conv,
         args: ['input', echo, case])
  endforeach
endforeach

foreach case: ['invalid-style', 'invalid-after-text', 'read-error',
              'read-error-after-response']
  test('misc_conv failure ' + case, tst_misc_conv, args: ['failure', case])
endforeach

foreach case: ['copy', 'replace', 'missing-handler', 'null-payload',
              'handler-failure', 'handler-null', 'cleanup-default',
              'cleanup-custom', 'cleanup-multiple']
  test('misc_conv binary ' + case, tst_misc_conv, args: ['binary', case])
endforeach

pkgconfig.generate(
  libpam_misc,
  description: 'Miscellaneous functions that make the job of writing PAM-aware applications easier.',
  name: 'pam_misc',
  filebase: 'pam_misc',
  version: pam_version_numeric,
  url: 'http://www.linux-pam.org/'
)
