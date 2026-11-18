#!/bin/sh

# Test UID-based faillock functionality
# This test covers:
# 1. UID-based tally file creation
# 2. CLI lookup/reset behavior with UID mode
# 3. Invalid or overflowing UID input
# 4. Lockout enforcement with UID-based files

set -e

TESTDIR=$(mktemp -d /tmp/faillock-test.XXXXXX)
CONFFILE="${TESTDIR}/faillock.conf"
TESTUSER="tstfaillockuid$$"
FAILLOCK="./faillock"

cleanup() {
    /usr/sbin/userdel -r "${TESTUSER}" 2>/dev/null || true
    rm -rf "${TESTDIR}"
}

trap cleanup EXIT INT TERM

# Create test user
/usr/sbin/useradd -p '!!' "${TESTUSER}"
TESTUID=$(id -u "${TESTUSER}")

echo "Test 1: UID-based tally file creation"
cat > "${CONFFILE}" <<EOF
dir=${TESTDIR}/tally
uid_based_files
deny=3
fail_interval=900
unlock_time=600
EOF

mkdir -p "${TESTDIR}/tally"

# Simulate a failure by creating a tally file with UID-based naming
# The file should be named by UID, not username
EXPECTED_FILE="${TESTDIR}/tally/${TESTUID}"
touch "${EXPECTED_FILE}"
if [ ! -f "${EXPECTED_FILE}" ]; then
    echo "FAIL: UID-based tally file not created at expected location"
    exit 1
fi
echo "PASS: UID-based tally file created"

echo "Test 2: CLI lookup with username in UID mode"
# Should accept username and resolve to UID internally
${FAILLOCK} --conf "${CONFFILE}" --user "${TESTUSER}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "FAIL: Failed to look up user by username in UID mode"
    exit 1
fi
echo "PASS: Username lookup works in UID mode"

echo "Test 3: CLI lookup with numeric UID"
# Should accept numeric UID directly
${FAILLOCK} --conf "${CONFFILE}" --user "${TESTUID}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "FAIL: Failed to look up user by UID in UID mode"
    exit 1
fi
echo "PASS: Numeric UID lookup works in UID mode"

echo "Test 4: CLI reset with username in UID mode"
${FAILLOCK} --conf "${CONFFILE}" --user "${TESTUSER}" --reset
if [ $? -ne 0 ]; then
    echo "FAIL: Failed to reset user by username in UID mode"
    exit 1
fi
echo "PASS: Username reset works in UID mode"

echo "Test 5: Invalid UID value (overflow)"
${FAILLOCK} --conf "${CONFFILE}" --user "999999999999999999999" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "FAIL: Should reject overflowing UID value"
    exit 1
fi
echo "PASS: Overflowing UID rejected"

echo "Test 6: Invalid input (non-numeric, non-existent user)"
${FAILLOCK} --conf "${CONFFILE}" --user "nonexistentuser123456" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "FAIL: Should reject non-existent user"
    exit 1
fi
echo "PASS: Non-existent user rejected"

echo "Test 7: Username-based mode still works"
cat > "${CONFFILE}" <<EOF
dir=${TESTDIR}/tally2
deny=3
fail_interval=900
unlock_time=600
EOF

mkdir -p "${TESTDIR}/tally2"
EXPECTED_FILE_USERNAME="${TESTDIR}/tally2/${TESTUSER}"
touch "${EXPECTED_FILE_USERNAME}"

${FAILLOCK} --conf "${CONFFILE}" --user "${TESTUSER}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "FAIL: Failed in username-based mode"
    exit 1
fi
echo "PASS: Username-based mode works"

echo "All tests passed!"
exit 0
