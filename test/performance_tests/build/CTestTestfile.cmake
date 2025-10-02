# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/performance_tests/build
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/performance_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Performance_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/performance_tests")
set_tests_properties(Performance_Basic_Tests PROPERTIES  LABELS "basic;performance" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;110;add_test;/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;0;")
add_test(Performance_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/performance_tests_asan")
set_tests_properties(Performance_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;performance" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;111;add_test;/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;0;")
add_test(Performance_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/performance_tests_tsan")
set_tests_properties(Performance_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;performance" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;112;add_test;/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;0;")
add_test(Performance_Coverage "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/performance_tests_coverage")
set_tests_properties(Performance_Coverage PROPERTIES  LABELS "coverage;performance" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;113;add_test;/home/haaken/github-projects/fgcom-mumble/test/performance_tests/build/CMakeLists.txt;0;")
