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

libpamc_test_targets = []

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
  libpamc_test_targets += tst_pam_bp
endforeach

pamc_test_agent = executable(
  'tst-pamc-agent',
  sources: 'tst-pamc-agent.c',
  include_directories: [libpam_inc, libpamc_inc],
  link_args: exe_link_args,
)

pamc_test_fixture = static_library(
  'pamc-test-fixture',
  sources: 'tst-pamc-fixture.c',
  include_directories: [libpam_inc],
)

tst_pamc_agent = executable(
  'tst-pamc_agent',
  sources: 'tst-pamc_agent.c',
  include_directories: [libpam_inc, libpamc_inc],
  link_with: [pamc_test_fixture, libpamc],
  link_args: exe_link_args,
)

test(
  'tst-pamc_agent', tst_pamc_agent,
  args: [pamc_test_agent],
  env: ['TMPDIR=' + meson.current_build_dir()],
  suite: 'libpamc',
  timeout: 30,
)

pamc_test_agent_alternate = executable(
  'tst-pamc-agent-alternate',
  sources: 'tst-pamc-agent.c',
  include_directories: [libpam_inc, libpamc_inc],
  c_args: ['-DPAMC_TEST_VARIANT=1'],
  link_args: exe_link_args,
)
libpamc_test_targets += [pamc_test_agent, pamc_test_agent_alternate, tst_pamc_agent]

foreach name: ['client', 'load', 'converse']
  tst_name = 'tst-pamc_' + name
  tst_exe = executable(
    tst_name,
    sources: tst_name + '.c',
    include_directories: [libpam_inc, libpamc_inc],
    link_with: [pamc_test_fixture, libpamc],
    link_args: exe_link_args,
  )
  tst_args = [pamc_test_agent]
  libpamc_test_targets += tst_exe
  if name == 'load'
    tst_args += pamc_test_agent_alternate
  endif
  test(
    tst_name, tst_exe,
    args: tst_args,
    env: ['TMPDIR=' + meson.current_build_dir()],
    suite: 'libpamc',
    timeout: 30,
  )
endforeach

# A private build makes the conversation's I/O injectable without exporting
# internal symbols from the shared library.  The ordinary target above still
# tests the installed-style shared library without seams.
pamc_inject_c_args = ['-include', meson.current_source_dir() / 'tst-pamc-inject.h']
pamc_test_converse = static_library(
  'pamc-test-converse',
  sources: libpamc_src,
  include_directories: [libpam_inc, libpamc_inc, libpam_internal_inc],
  dependencies: [libpam_internal_dep],
  c_args: pamc_inject_c_args + ['-DPAMC_TEST_IO'],
)
tst_pamc_converse_io = executable(
  'tst-pamc_converse-io',
  sources: ['tst-pamc_converse.c', 'tst-pamc-io.c'],
  include_directories: [libpam_inc, libpamc_inc],
  c_args: ['-DPAMC_TEST_IO'],
  link_with: [pamc_test_converse, pamc_test_fixture],
  link_args: exe_link_args,
)
test(
  'tst-pamc_converse-io', tst_pamc_converse_io,
  args: [pamc_test_agent],
  env: ['TMPDIR=' + meson.current_build_dir()],
  suite: 'libpamc',
  timeout: 30,
)
libpamc_test_targets += tst_pamc_converse_io

pamc_fault_c_args = pamc_inject_c_args + ['-DPAMC_TEST_FAULTS']
foreach ndebug: [false, true]
  suffix = ndebug ? '-ndebug' : ''
  mode_args = [ndebug ? '-DNDEBUG' : '-UNDEBUG']
  pamc_fault_lib = static_library(
    'pamc-test-faults' + suffix,
    sources: libpamc_src,
    include_directories: [libpam_inc, libpamc_inc, libpam_internal_inc],
    dependencies: [libpam_internal_dep],
    c_args: pamc_fault_c_args + mode_args,
  )
  tst_name = 'tst-pamc_faults' + suffix
  tst_exe = executable(
    tst_name,
    sources: ['tst-pamc_faults.c', 'tst-pamc-faults.c'],
    include_directories: [libpam_inc, libpamc_inc],
    c_args: mode_args,
    link_with: [pamc_fault_lib, pamc_test_fixture],
    link_args: exe_link_args,
  )
  libpamc_test_targets += tst_exe
  test(
    tst_name, tst_exe,
    args: [pamc_test_agent],
    env: ['TMPDIR=' + meson.current_build_dir()],
    suite: 'libpamc',
    timeout: 30,
  )
endforeach

# Build only this suite, including helper executables, for sanitizer checks.
alias_target('libpamc-tests', libpamc_test_targets)
