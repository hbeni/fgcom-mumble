# CMake generated Testfile for 
# Source directory: /home/haaken/fgcom-mumble/test/integration_tests
# Build directory: /home/haaken/fgcom-mumble/test/integration_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(integration_tests "/home/haaken/fgcom-mumble/test/integration_tests/build/integration_tests")
set_tests_properties(integration_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/integration_tests/CMakeLists.txt;49;add_test;/home/haaken/fgcom-mumble/test/integration_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
