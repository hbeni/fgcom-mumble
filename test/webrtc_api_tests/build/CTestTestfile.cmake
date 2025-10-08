# CMake generated Testfile for 
# Source directory: /home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests
# Build directory: /home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(WebRTC_API_Basic_Tests "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/build/webrtc_api_tests")
set_tests_properties(WebRTC_API_Basic_Tests PROPERTIES  LABELS "basic;webrtc" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;187;add_test;/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;0;")
add_test(WebRTC_API_AddressSanitizer "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/build/webrtc_api_tests_asan")
set_tests_properties(WebRTC_API_AddressSanitizer PROPERTIES  LABELS "sanitizer;memory;webrtc" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;188;add_test;/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;0;")
add_test(WebRTC_API_ThreadSanitizer "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/build/webrtc_api_tests_tsan")
set_tests_properties(WebRTC_API_ThreadSanitizer PROPERTIES  LABELS "sanitizer;thread;webrtc" TIMEOUT "600" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;189;add_test;/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;0;")
add_test(WebRTC_API_Coverage "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/build/webrtc_api_tests_coverage")
set_tests_properties(WebRTC_API_Coverage PROPERTIES  LABELS "coverage;webrtc" TIMEOUT "300" _BACKTRACE_TRIPLES "/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;190;add_test;/home/haaken/github-projects/fgcom-mumble/test/webrtc_api_tests/CMakeLists.txt;0;")
subdirs("rapidcheck")
