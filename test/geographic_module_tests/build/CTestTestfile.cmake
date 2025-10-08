# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Geographic_Module_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/build/geographic_module_tests")
set_tests_properties(Geographic_Module_Basic_Tests PROPERTIES  LABELS "basic;geographic_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;157;add_test;/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;0;")
add_test(Geographic_Module_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/build/geographic_module_tests_asan")
set_tests_properties(Geographic_Module_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;geographic_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;158;add_test;/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;0;")
add_test(Geographic_Module_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/build/geographic_module_tests_tsan")
set_tests_properties(Geographic_Module_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;geographic_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;159;add_test;/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;0;")
add_test(Geographic_Module_Coverage "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/build/geographic_module_tests_coverage")
set_tests_properties(Geographic_Module_Coverage PROPERTIES  LABELS "coverage;geographic_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;160;add_test;/home/haaken/github-projects/fgcom-mumble/test/geographic_module_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
