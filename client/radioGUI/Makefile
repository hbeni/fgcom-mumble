# Makefile for radioGUI
# Java Maven project for FGCom-mumble Radio GUI

# Project configuration
PROJECT_NAME = FGCom-mumble-radioGUI
MAVEN = mvn
JAVA = java

# Default target
all: compile

# Clean the project
clean:
	$(MAVEN) clean

# Compile the project
compile: clean
	$(MAVEN) compile

# Package the project
package: compile
	$(MAVEN) package

# Install dependencies
install:
	$(MAVEN) install

# Run tests
test: compile
	$(MAVEN) test

# Run the application
run: package
	$(JAVA) -jar target/$(PROJECT_NAME)-1.2.0.jar

# Run with specific profile
run-with-jsimconnect: package
	$(MAVEN) exec:java -Pjsimconnect

run-without-jsimconnect: package
	$(MAVEN) exec:java -Pno-jsimconnect

# Build without JSIMConnect
build-without-jsimconnect:
	$(MAVEN) clean package -Pno-jsimconnect

# Build with JSIMConnect
build-with-jsimconnect:
	$(MAVEN) clean package -Pjsimconnect

# Install JSIMConnect dependency
install-jsimconnect:
	$(MAVEN) install:install-file \
		-Dfile=lib/jsimconnect-0.8.0.jar \
		-DgroupId=flightsim \
		-DartifactId=jsimconnect \
		-Dversion=0.8.0 \
		-Dpackaging=jar

# Generate site documentation
site:
	$(MAVEN) site

# Run with specific JVM options
run-debug: package
	$(JAVA) -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005 -jar target/$(PROJECT_NAME)-1.2.0.jar

# Run with memory options
run-memory: package
	$(JAVA) -Xmx2g -Xms1g -jar target/$(PROJECT_NAME)-1.2.0.jar

# Check dependencies
deps:
	$(MAVEN) dependency:tree

# Check for updates
updates:
	$(MAVEN) versions:display-dependency-updates

# Validate POM
validate:
	$(MAVEN) validate

# Generate sources
generate-sources:
	$(MAVEN) generate-sources

# Help
help:
	@echo "Available targets:"
	@echo "  all                    - Compile the project"
	@echo "  clean                  - Clean the project"
	@echo "  compile                - Compile the project"
	@echo "  package                - Package the project"
	@echo "  install                - Install dependencies"
	@echo "  test                   - Run tests"
	@echo "  run                    - Run the application"
	@echo "  run-with-jsimconnect  - Run with JSIMConnect support"
	@echo "  run-without-jsimconnect- Run without JSIMConnect"
	@echo "  build-without-jsimconnect - Build without JSIMConnect"
	@echo "  build-with-jsimconnect - Build with JSIMConnect"
	@echo "  install-jsimconnect    - Install JSIMConnect dependency"
	@echo "  site                   - Generate site documentation"
	@echo "  run-debug              - Run with debug options"
	@echo "  run-memory             - Run with memory options"
	@echo "  deps                   - Check dependencies"
	@echo "  updates                - Check for updates"
	@echo "  validate               - Validate POM"
	@echo "  generate-sources       - Generate sources"
	@echo "  help                   - Show this help"

.PHONY: all clean compile package install test run run-with-jsimconnect run-without-jsimconnect build-without-jsimconnect build-with-jsimconnect install-jsimconnect site run-debug run-memory deps updates validate generate-sources help
