# Master Makefile for all test suites
# This Makefile provides unified build management for all test suites

# List of all test suites
TEST_SUITES = agc_squelch_tests antenna_pattern_module_tests atis_module_tests audio_processing_tests client_plugin_module_tests database_configuration_module_tests error_handling_tests frequency_management_tests geographic_module_tests integration_tests jsimconnect_build_tests network_module_tests openstreetmap_infrastructure_tests performance_tests professional_audio_tests radio_propagation_tests security_module_tests status_page_module_tests webrtc_api_tests work_unit_distribution_module_tests

# Default target
all: build-all

# Build all test suites
build-all:
	@echo "Building all test suites..."
	@for suite in $(TEST_SUITES); do \
		if [ -d "$$suite" ]; then \
			echo "Building $$suite..."; \
			cd $$suite && make build 2>/dev/null || make all 2>/dev/null || echo "Failed to build $$suite"; \
			cd ..; \
		else \
			echo "Directory $$suite not found, skipping..."; \
		fi; \
	done

# Run all tests
test-all:
	@echo "Running all test suites..."
	@for suite in $(TEST_SUITES); do \
		if [ -d "$$suite" ]; then \
			echo "Running $$suite..."; \
			cd $$suite && make test 2>/dev/null || echo "Failed to run $$suite"; \
			cd ..; \
		fi; \
	done

# Run tests with verbose output
test-verbose-all:
	@echo "Running all test suites with verbose output..."
	@for suite in $(TEST_SUITES); do \
		if [ -d "$$suite" ]; then \
			echo "Running $$suite (verbose)..."; \
			cd $$suite && make test-verbose 2>/dev/null || echo "Failed to run $$suite"; \
			cd ..; \
		fi; \
	done

# Clean all test suites
clean-all:
	@echo "Cleaning all test suites..."
	@for suite in $(TEST_SUITES); do \
		if [ -d "$$suite" ]; then \
			echo "Cleaning $$suite..."; \
			cd $$suite && make clean 2>/dev/null || echo "Failed to clean $$suite"; \
			cd ..; \
		fi; \
	done

# Clean everything including build directories
distclean-all:
	@echo "Distcleaning all test suites..."
	@for suite in $(TEST_SUITES); do \
		if [ -d "$$suite" ]; then \
			echo "Distcleaning $$suite..."; \
			cd $$suite && make distclean 2>/dev/null || echo "Failed to distclean $$suite"; \
			cd ..; \
		fi; \
	done

# Show help for all test suites
help-all:
	@echo "Available targets for all test suites:"
	@echo "  all            - Build all test suites"
	@echo "  build-all      - Build all test suites"
	@echo "  test-all       - Run all test suites"
	@echo "  test-verbose-all - Run all test suites with verbose output"
	@echo "  clean-all      - Clean all test suites"
	@echo "  distclean-all  - Clean everything including build directories"
	@echo "  help-all       - Show this help message"
	@echo ""
	@echo "Individual test suite usage:"
	@echo "  cd test/audio_processing_tests && make test"
	@echo "  cd test/error_handling_tests && make test-verbose"
	@echo "  cd test/performance_tests && make test-coverage"
	@echo "  cd test/network_module_tests && make test-filter FILTER=*UDP*"

# Show help
help: help-all

# Phony targets
.PHONY: all build-all test-all test-verbose-all clean-all distclean-all help-all help
