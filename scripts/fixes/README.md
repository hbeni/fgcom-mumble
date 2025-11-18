# Fix Scripts Directory

This directory contains automated fix scripts for common issues, code quality improvements, and maintenance tasks in the FGcom-Mumble project.

## Scripts Overview

### `fix_braces.sh`
**Purpose**: Automatically fixes brace formatting issues in C++ code to ensure consistent coding style.

**Features**:
- Automatic brace placement correction
- Consistent indentation fixing
- Multi-line statement formatting
- Function definition standardization
- Class declaration formatting

**Usage**:
```bash
# Fix braces in all C++ files
./fix_braces.sh

# Fix braces in specific files
./fix_braces.sh --files src/voice_encryption.cpp

# Dry run to preview changes
./fix_braces.sh --dry-run

# Fix with specific style
./fix_braces.sh --style allman
```

**Supported Styles**:
- `allman` - Allman style braces
- `k&r` - Kernighan & Ritchie style
- `stroustrup` - Stroustrup style
- `whitesmiths` - Whitesmiths style

### `fix_clang_tidy.sh`
**Purpose**: Automatically fixes issues identified by clang-tidy static analysis.

**Features**:
- Automatic clang-tidy issue resolution
- Code quality improvements
- Performance optimization fixes
- Memory management fixes
- Modern C++ feature adoption

**Usage**:
```bash
# Fix all clang-tidy issues
./fix_clang_tidy.sh

# Fix specific issue types
./fix_clang_tidy.sh --fixes readability,performance

# Preview fixes before applying
./fix_clang_tidy.sh --dry-run

# Fix with specific checks
./fix_clang_tidy.sh --checks modernize-*,readability-*
```

**Supported Fixes**:
- `modernize-*` - Modern C++ features
- `readability-*` - Code readability improvements
- `performance-*` - Performance optimizations
- `cppcoreguidelines-*` - C++ Core Guidelines compliance

## Fix Categories

### Code Style Fixes
- Brace formatting
- Indentation consistency
- Line length compliance
- Comment formatting
- Naming convention fixes

### Performance Fixes
- Loop optimization
- Memory allocation improvements
- Function inlining
- Const correctness
- Move semantics

### Modern C++ Fixes
- Auto keyword usage
- Range-based loops
- Smart pointers
- Lambda expressions
- Template improvements

### Security Fixes
- Buffer overflow prevention
- Input validation
- Memory leak fixes
- Exception safety
- Resource management

## Usage Examples

### Fix All Issues
```bash
# Run all fix scripts
./fix_braces.sh && ./fix_clang_tidy.sh

# Fix with validation
./fix_braces.sh --validate && ./fix_clang_tidy.sh --validate
```

### Selective Fixing
```bash
# Fix only specific files
./fix_braces.sh --files src/voice_encryption.cpp src/radio_propagation.cpp

# Fix only specific issue types
./fix_clang_tidy.sh --fixes readability-*,performance-*
```

### Validation
```bash
# Dry run to preview changes
./fix_braces.sh --dry-run
./fix_clang_tidy.sh --dry-run

# Validate fixes
./fix_braces.sh --validate
./fix_clang_tidy.sh --validate
```

## Configuration

### Fix Settings
- `fix_config.json` - Fix script configuration
- `style_rules.conf` - Code style rules
- `clang_tidy_config.yaml` - Clang-tidy configuration

### Exclude Patterns
- `exclude_files.txt` - Files to exclude from fixes
- `exclude_directories.txt` - Directories to exclude
- `exclude_patterns.txt` - Pattern-based exclusions

## Integration

### With Development Workflow
```bash
# Pre-commit fixes
./fix_braces.sh --pre-commit
./fix_clang_tidy.sh --pre-commit

# Post-commit validation
./fix_braces.sh --validate
./fix_clang_tidy.sh --validate
```

### With CI/CD
```bash
# CI fix validation
./fix_braces.sh --ci-mode
./fix_clang_tidy.sh --ci-mode

# Automated fixing
./fix_braces.sh --auto-fix
./fix_clang_tidy.sh --auto-fix
```

## Safety Features

### Backup Creation
- Automatic backup before fixes
- Version control integration
- Rollback capability
- Change tracking

### Validation
- Fix validation before application
- Syntax checking
- Compilation testing
- Test suite validation

### Rollback
- Automatic rollback on failure
- Manual rollback capability
- Change history tracking
- Backup restoration

## Best Practices

### Before Running Fixes
1. **Backup Code**: Ensure code is backed up
2. **Review Changes**: Use dry-run mode first
3. **Test Environment**: Run in test environment
4. **Incremental Fixes**: Fix issues incrementally
5. **Validation**: Validate fixes after application

### After Running Fixes
1. **Compile Test**: Ensure code compiles
2. **Test Suite**: Run test suite
3. **Code Review**: Review changes
4. **Documentation**: Update documentation if needed
5. **Commit**: Commit changes with descriptive messages

## Troubleshooting

### Common Issues

1. **Fix Scripts Not Working**
   ```bash
   # Check permissions
   chmod +x fix_*.sh
   # Check dependencies
   ./fix_braces.sh --check-deps
   ```

2. **Clang-tidy Not Found**
   ```bash
   # Install clang-tidy
   sudo apt-get install clang-tidy
   # Check installation
   which clang-tidy
   ```

3. **Fix Validation Fails**
   ```bash
   # Check syntax
   ./fix_braces.sh --syntax-check
   # Validate configuration
   ./fix_clang_tidy.sh --validate-config
   ```

### Recovery

1. **Rollback Changes**
   ```bash
   # Automatic rollback
   ./fix_braces.sh --rollback
   ./fix_clang_tidy.sh --rollback
   ```

2. **Restore Backup**
   ```bash
   # Restore from backup
   ./fix_braces.sh --restore-backup
   ./fix_clang_tidy.sh --restore-backup
   ```

## Monitoring

### Fix Tracking
- Fix history logging
- Change impact analysis
- Performance monitoring
- Quality metrics tracking

### Reports
- Fix summary reports
- Quality improvement reports
- Performance impact reports
- Compliance reports

## Future Enhancements

- Machine learning-based fixes
- Custom fix rules
- Integration with IDEs
- Real-time fix suggestions
- Automated testing integration

## Support

For fix script issues:
1. Check script permissions
2. Verify dependencies
3. Review configuration
4. Check log files
5. Validate input files
