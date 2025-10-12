# CMake generated Testfile for 
# Source directory: /home/haaken/fgcom-mumble/test/frequency_management_tests
# Build directory: /home/haaken/fgcom-mumble/test/frequency_management_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Frequency_Management_Basic_Tests "/home/haaken/fgcom-mumble/test/frequency_management_tests/build/frequency_management_tests")
set_tests_properties(Frequency_Management_Basic_Tests PROPERTIES  LABELS "basic;frequency_management" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;161;add_test;/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;0;")
add_test(Frequency_Management_AddressSanitizer "/home/haaken/fgcom-mumble/test/frequency_management_tests/build/frequency_management_tests_asan")
set_tests_properties(Frequency_Management_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;frequency_management" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;162;add_test;/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;0;")
add_test(Frequency_Management_ThreadSanitizer "/home/haaken/fgcom-mumble/test/frequency_management_tests/build/frequency_management_tests_tsan")
set_tests_properties(Frequency_Management_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;frequency_management" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;163;add_test;/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;0;")
add_test(Frequency_Management_Coverage "/home/haaken/fgcom-mumble/test/frequency_management_tests/build/frequency_management_tests_coverage")
set_tests_properties(Frequency_Management_Coverage PROPERTIES  LABELS "coverage;frequency_management" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;164;add_test;/home/haaken/fgcom-mumble/test/frequency_management_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
