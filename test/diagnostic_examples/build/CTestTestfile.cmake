# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/diagnostic_examples
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/diagnostic_examples/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(diagnostic_examples "/home/haaken/github-projects/fgcom-mumble/test/diagnostic_examples/build/diagnostic_examples")
set_tests_properties(diagnostic_examples PROPERTIES  _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/diagnostic_examples/CMakeLists.txt;50;add_test;/home/haaken/github-projects/fgcom-mumble/test/diagnostic_examples/CMakeLists.txt;0;")
subdirs("rapidcheck")
