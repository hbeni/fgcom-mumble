# CMake generated Testfile for 
# Source directory: /home/haaken/fgcom-mumble/test/edge_case_coverage_tests
# Build directory: /home/haaken/fgcom-mumble/test/edge_case_coverage_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(edge_case_coverage_tests "/home/haaken/fgcom-mumble/test/edge_case_coverage_tests/build/edge_case_coverage_tests")
set_tests_properties(edge_case_coverage_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/edge_case_coverage_tests/CMakeLists.txt;73;add_test;/home/haaken/fgcom-mumble/test/edge_case_coverage_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
