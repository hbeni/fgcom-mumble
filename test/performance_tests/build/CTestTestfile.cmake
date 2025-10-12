# CMake generated Testfile for 
# Source directory: /home/haaken/fgcom-mumble/test/performance_tests
# Build directory: /home/haaken/fgcom-mumble/test/performance_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(performance_tests "/home/haaken/fgcom-mumble/test/performance_tests/build/performance_tests")
set_tests_properties(performance_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/haaken/fgcom-mumble/test/performance_tests/CMakeLists.txt;52;add_test;/home/haaken/fgcom-mumble/test/performance_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
