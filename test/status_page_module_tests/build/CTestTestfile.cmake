# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(StatusPageModule_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/build/status_page_module_tests")
set_tests_properties(StatusPageModule_Basic_Tests PROPERTIES  LABELS "basic;status_page_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;159;add_test;/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;0;")
add_test(StatusPageModule_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/build/status_page_module_tests_asan")
set_tests_properties(StatusPageModule_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;status_page_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;160;add_test;/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;0;")
add_test(StatusPageModule_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/build/status_page_module_tests_tsan")
set_tests_properties(StatusPageModule_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;status_page_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;161;add_test;/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;0;")
add_test(StatusPageModule_Coverage "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/build/status_page_module_tests_coverage")
set_tests_properties(StatusPageModule_Coverage PROPERTIES  LABELS "coverage;status_page_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;162;add_test;/home/haaken/github-projects/fgcom-mumble/test/status_page_module_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
