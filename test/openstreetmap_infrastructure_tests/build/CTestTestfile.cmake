# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(OpenStreetMap_Infrastructure_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/build/openstreetmap_infrastructure_tests")
set_tests_properties(OpenStreetMap_Infrastructure_Basic_Tests PROPERTIES  LABELS "basic;openstreetmap;infrastructure" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;155;add_test;/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;0;")
add_test(OpenStreetMap_Infrastructure_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/build/openstreetmap_infrastructure_tests_asan")
set_tests_properties(OpenStreetMap_Infrastructure_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;openstreetmap;infrastructure" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;156;add_test;/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;0;")
add_test(OpenStreetMap_Infrastructure_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/build/openstreetmap_infrastructure_tests_tsan")
set_tests_properties(OpenStreetMap_Infrastructure_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;openstreetmap;infrastructure" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;157;add_test;/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;0;")
add_test(OpenStreetMap_Infrastructure_Coverage "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/build/openstreetmap_infrastructure_tests_coverage")
set_tests_properties(OpenStreetMap_Infrastructure_Coverage PROPERTIES  LABELS "coverage;openstreetmap;infrastructure" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;158;add_test;/home/haaken/github-projects/fgcom-mumble/test/openstreetmap_infrastructure_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
