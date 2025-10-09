# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(WorkUnitDistributionModule_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/build/work_unit_distribution_module_tests")
set_tests_properties(WorkUnitDistributionModule_Basic_Tests PROPERTIES  LABELS "basic;work_unit_distribution_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;155;add_test;/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;0;")
add_test(WorkUnitDistributionModule_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/build/work_unit_distribution_module_tests_asan")
set_tests_properties(WorkUnitDistributionModule_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;work_unit_distribution_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;156;add_test;/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;0;")
add_test(WorkUnitDistributionModule_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/build/work_unit_distribution_module_tests_tsan")
set_tests_properties(WorkUnitDistributionModule_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;work_unit_distribution_module" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;157;add_test;/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;0;")
add_test(WorkUnitDistributionModule_Coverage "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/build/work_unit_distribution_module_tests_coverage")
set_tests_properties(WorkUnitDistributionModule_Coverage PROPERTIES  LABELS "coverage;work_unit_distribution_module" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;158;add_test;/home/haaken/github-projects/fgcom-mumble/test/work_unit_distribution_module_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
