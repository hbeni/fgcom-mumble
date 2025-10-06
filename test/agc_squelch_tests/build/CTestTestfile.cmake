# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(AGC_Squelch_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/build/agc_squelch_tests")
set_tests_properties(AGC_Squelch_Basic_Tests PROPERTIES  LABELS "basic" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;128;add_test;/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;0;")
add_test(AGC_Squelch_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/build/agc_squelch_tests_asan")
set_tests_properties(AGC_Squelch_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;129;add_test;/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;0;")
add_test(AGC_Squelch_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/build/agc_squelch_tests_tsan")
set_tests_properties(AGC_Squelch_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;130;add_test;/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;0;")
add_test(AGC_Squelch_Coverage "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/build/agc_squelch_tests_coverage")
set_tests_properties(AGC_Squelch_Coverage PROPERTIES  LABELS "coverage" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;131;add_test;/home/haaken/github-projects/fgcom-mumble/test/agc_squelch_tests/CMakeLists.txt;0;")
