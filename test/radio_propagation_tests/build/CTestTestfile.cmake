# CMake generated Testfile for 
# Source directory: /home/haaken/fgcom-mumble/test/radio_propagation_tests
# Build directory: /home/haaken/fgcom-mumble/test/radio_propagation_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Radio_Propagation_Basic_Tests "/home/haaken/fgcom-mumble/test/radio_propagation_tests/build/radio_propagation_tests")
set_tests_properties(Radio_Propagation_Basic_Tests PROPERTIES  LABELS "basic;radio_propagation" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;163;add_test;/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;0;")
add_test(Radio_Propagation_AddressSanitizer "/home/haaken/fgcom-mumble/test/radio_propagation_tests/build/radio_propagation_tests_asan")
set_tests_properties(Radio_Propagation_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;radio_propagation" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;164;add_test;/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;0;")
add_test(Radio_Propagation_ThreadSanitizer "/home/haaken/fgcom-mumble/test/radio_propagation_tests/build/radio_propagation_tests_tsan")
set_tests_properties(Radio_Propagation_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;radio_propagation" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;165;add_test;/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;0;")
add_test(Radio_Propagation_Coverage "/home/haaken/fgcom-mumble/test/radio_propagation_tests/build/radio_propagation_tests_coverage")
set_tests_properties(Radio_Propagation_Coverage PROPERTIES  LABELS "coverage;radio_propagation" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;166;add_test;/home/haaken/fgcom-mumble/test/radio_propagation_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
