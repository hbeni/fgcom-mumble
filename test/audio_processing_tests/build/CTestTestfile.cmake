# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Audio_Processing_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/build/audio_processing_tests")
set_tests_properties(Audio_Processing_Basic_Tests PROPERTIES  LABELS "basic;audio_processing" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;120;add_test;/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;0;")
add_test(Audio_Processing_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/build/audio_processing_tests_asan")
set_tests_properties(Audio_Processing_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;audio_processing" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;121;add_test;/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;0;")
add_test(Audio_Processing_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/build/audio_processing_tests_tsan")
set_tests_properties(Audio_Processing_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;audio_processing" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;122;add_test;/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;0;")
add_test(Audio_Processing_Coverage "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/build/audio_processing_tests_coverage")
set_tests_properties(Audio_Processing_Coverage PROPERTIES  LABELS "coverage;audio_processing" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;123;add_test;/home/haaken/github-projects/fgcom-mumble/test/audio_processing_tests/CMakeLists.txt;0;")
