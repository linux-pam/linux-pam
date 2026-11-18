subdir('include/security')

libpamc_src = [
  'pamc_client.c',
  'pamc_converse.c',
  'pamc_load.c',
]

libpamc_inc = include_directories('include')

libpamc_version = '0.82.1'
libpamc_map = 'libpamc.map'
libpamc_map_path = meson.current_source_dir() / libpamc_map

libpamc_link_deps = [libpamc_map]
libpamc_link_args = ['-Wl,--version-script=' + libpamc_map_path]

libpamc = shared_library(
  'pamc',
  sources: libpamc_src,
  include_directories: [libpam_inc, libpamc_inc],
  dependencies: [libpam_internal_dep],
  link_depends: libpamc_link_deps,
  link_args: libpamc_link_args,
  version: libpamc_version,
  install: true,
)

pkgconfig.generate(
  libpamc,
  description: 'The PAM client API library and binary prompt support. Rarely used.',
  name: 'libpamc',
  filebase: 'pamc',
  version: pam_version_numeric,
  url: 'http://www.linux-pam.org/'
)

# The macros' unsigned comparisons against zero warn for some boundary cases.
pam_bp_test_c_args = cc.get_supported_arguments(['-Wno-type-limits'])

foreach ndebug: [false, true]
  tst_name = 'tst-pam_bp' + (ndebug ? '-ndebug' : '')
  tst_pam_bp = executable(
    tst_name,
    sources: 'tst-pam_bp.c',
    include_directories: [libpam_inc, libpamc_inc],
    c_args: pam_bp_test_c_args + [ndebug ? '-DNDEBUG' : '-UNDEBUG'],
    link_args: exe_link_args,
  )

  test(tst_name, tst_pam_bp, suite: 'libpamc')
endforeach
