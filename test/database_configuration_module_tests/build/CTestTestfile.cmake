# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(DatabaseConfigurationModule_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/build/database_configuration_module_tests")
set_tests_properties(DatabaseConfigurationModule_Basic_Tests PROPERTIES  LABELS "basic;database_configuration_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;116;add_test;/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;0;")
add_test(DatabaseConfigurationModule_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/build/database_configuration_module_tests_asan")
set_tests_properties(DatabaseConfigurationModule_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;database_configuration_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;117;add_test;/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;0;")
add_test(DatabaseConfigurationModule_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/build/database_configuration_module_tests_tsan")
set_tests_properties(DatabaseConfigurationModule_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;database_configuration_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;118;add_test;/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;0;")
add_test(DatabaseConfigurationModule_Coverage "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/build/database_configuration_module_tests_coverage")
set_tests_properties(DatabaseConfigurationModule_Coverage PROPERTIES  LABELS "coverage;database_configuration_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;119;add_test;/home/haaken/github-projects/fgcom-mumble/test/database_configuration_module_tests/CMakeLists.txt;0;")
