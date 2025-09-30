# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/network_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/network_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Network_Module_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/build/network_module_tests")
set_tests_properties(Network_Module_Basic_Tests PROPERTIES  LABELS "basic;network_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;149;add_test;/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;0;")
add_test(Network_Module_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/build/network_module_tests_asan")
set_tests_properties(Network_Module_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;network_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;150;add_test;/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;0;")
add_test(Network_Module_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/build/network_module_tests_tsan")
set_tests_properties(Network_Module_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;network_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;151;add_test;/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;0;")
add_test(Network_Module_Coverage "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/build/network_module_tests_coverage")
set_tests_properties(Network_Module_Coverage PROPERTIES  LABELS "coverage;network_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;152;add_test;/home/haaken/github-projects/fgcom-mumble/test/network_module_tests/CMakeLists.txt;0;")
