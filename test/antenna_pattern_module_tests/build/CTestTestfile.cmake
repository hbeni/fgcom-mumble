# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(AntennaPatternModule_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/build/antenna_pattern_module_tests")
set_tests_properties(AntennaPatternModule_Basic_Tests PROPERTIES  LABELS "basic;antenna_pattern_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;118;add_test;/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;0;")
add_test(AntennaPatternModule_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/build/antenna_pattern_module_tests_asan")
set_tests_properties(AntennaPatternModule_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;antenna_pattern_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;119;add_test;/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;0;")
add_test(AntennaPatternModule_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/build/antenna_pattern_module_tests_tsan")
set_tests_properties(AntennaPatternModule_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;antenna_pattern_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;120;add_test;/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;0;")
add_test(AntennaPatternModule_Coverage "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/build/antenna_pattern_module_tests_coverage")
set_tests_properties(AntennaPatternModule_Coverage PROPERTIES  LABELS "coverage;antenna_pattern_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;121;add_test;/home/haaken/github-projects/fgcom-mumble/test/antenna_pattern_module_tests/CMakeLists.txt;0;")
