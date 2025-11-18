# Analysis Scripts Directory

This directory contains scripts for code analysis, static analysis, and quality assurance tools used in the FGcom-Mumble project.

## Scripts Overview

### `clang-tidy-analysis.sh`
**Purpose**: Performs static code analysis using clang-tidy to identify potential issues, code quality problems, and style violations.

**Features**:
- Comprehensive static analysis using clang-tidy
- Configurable analysis levels (basic, medium, strict)
- Output formatting for easy review
- Integration with CI/CD pipelines
- Support for multiple C++ standards

**Usage**:
```bash
# Basic analysis
./clang-tidy-analysis.sh

# Strict analysis with all checks
./clang-tidy-analysis.sh --strict

# Analyze specific files
./clang-tidy-analysis.sh --files src/voice_encryption.cpp

# Generate HTML report
./clang-tidy-analysis.sh --html-report
```

**Configuration**:
- Analysis level: `--basic`, `--medium`, `--strict`
- Output format: `--text`, `--html`, `--json`
- File filtering: `--files <pattern>`
- Exclude patterns: `--exclude <pattern>`

**Output**:
- Text report to stdout
- HTML report in `analysis_output/`
- JSON report for CI integration
- Exit codes: 0 (clean), 1 (warnings), 2 (errors)

## Integration

### With CI/CD
```bash
# In CI pipeline
./scripts/analysis/clang-tidy-analysis.sh --strict --json > analysis.json
```

### With IDE
```bash
# Generate compile_commands.json for IDE integration
./scripts/analysis/clang-tidy-analysis.sh --generate-compile-commands
```

## Dependencies

- **clang-tidy**: Static analysis tool
- **clang**: C++ compiler
- **CMake**: Build system integration
- **Python3**: For report processing

## Configuration Files

- `.clang-tidy`: Clang-tidy configuration
- `analysis_config.json`: Analysis settings
- `exclude_patterns.txt`: Files/directories to exclude

## Troubleshooting

### Common Issues

1. **clang-tidy not found**
   ```bash
   # Install clang-tidy
   sudo apt-get install clang-tidy
   # or
   sudo yum install clang-tools-extra
   ```

2. **Compile commands not found**
   ```bash
   # Generate compile_commands.json
   cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
   ```

3. **Analysis too slow**
   ```bash
   # Use parallel analysis
   ./clang-tidy-analysis.sh --parallel 4
   ```

## Best Practices

1. **Regular Analysis**: Run analysis before commits
2. **Fix Issues**: Address all high-priority issues
3. **Update Config**: Keep .clang-tidy configuration current
4. **Review Reports**: Regularly review analysis reports
5. **Team Standards**: Ensure consistent analysis across team

## Future Enhancements

- Integration with other static analysis tools
- Custom rule definitions
- Historical analysis tracking
- Performance regression detection
- Automated fix suggestions

## Support

For issues with analysis scripts:
1. Check clang-tidy installation
2. Verify CMake configuration
3. Review analysis configuration
4. Check file permissions
5. Review log files in `logs/analysis/`
