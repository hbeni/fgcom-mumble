# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/atis_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(ATIS_Module_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/build/atis_module_tests")
set_tests_properties(ATIS_Module_Basic_Tests PROPERTIES  LABELS "basic;atis_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;165;add_test;/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;0;")
add_test(ATIS_Module_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/build/atis_module_tests_asan")
set_tests_properties(ATIS_Module_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;atis_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;166;add_test;/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;0;")
add_test(ATIS_Module_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/build/atis_module_tests_tsan")
set_tests_properties(ATIS_Module_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;atis_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;167;add_test;/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;0;")
add_test(ATIS_Module_Coverage "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/build/atis_module_tests_coverage")
set_tests_properties(ATIS_Module_Coverage PROPERTIES  LABELS "coverage;atis_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;168;add_test;/home/haaken/github-projects/fgcom-mumble/test/atis_module_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
