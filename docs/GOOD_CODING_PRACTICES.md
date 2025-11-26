# Good Coding Practices

## **THESE RULES ARE STRICT!**
## **THEY MUST BE ADHERED TO!**

---

## Architecture & Design

### **Separation of Concerns**
- Each function/module has a single, well-defined responsibility
- State management is isolated from business logic
- Hardware abstraction is separated from application logic

### **Predictable State Management**
- Clear state machines with defined transitions
- No race conditions or undefined states
- Atomic operations where needed

### **Scalability & Maintainability**
- Code can be modified without breaking existing functionality
- New features can be added without major refactoring
- Clear interfaces between components

---

## Code Quality

### **Readability**
- Self-documenting variable and function names
- Consistent formatting and style
- Logical code organization

### **Error Handling**
- Graceful handling of edge cases
- Proper validation of inputs
- Recovery mechanisms for failure scenarios

### **Documentation**
- Clear comments explaining why, not just what
- Function/module documentation
- System-level architectural documentation

---

## Reliability

### **Robustness**
- Handles unexpected inputs gracefully
- Resistant to timing issues and hardware variations
- Proper resource management (memory, timing, etc.)

### **Testing Considerations**
- Code structure allows for testing
- Deterministic behavior
- Observable state for debugging

---

## Performance

### **Efficiency**
- Appropriate algorithms for the problem domain
- Minimal resource usage
- Proper timing considerations for real-time systems

### **Responsiveness**
- Meets timing requirements consistently
- Proper priority handling

---

## Industry Standards

### **Coding Standards**
- Follows established conventions for the language/platform
- Consistent naming conventions
- Appropriate use of language features

### **Security**
- Input validation
- Proper access controls
- Secure coding practices

---

## **DO NOT BREAK THESE RULES!**

**Perform a deep and thorough code inspection to look for these errors.**
**Examine EVERY file systematically!**

---

## **CRITICAL ERRORS TO ELIMINATE**

### **Race Conditions**
- Multiple processes accessing shared data without proper synchronization
- State changes happening in unexpected order
- Concurrent WebSocket operations - multiple writes to the same connection without queuing
- Shared variable mutations - multiple functions modifying the same variable without locks/semaphores
- Event handler conflicts - multiple event handlers modifying the same DOM elements simultaneously
- Async function overlaps - Promise-based operations executing in parallel when they should be sequential

### **Undefined State Handling**
- Not considering what happens when systems are in unexpected states
- Missing edge case handling
- Assuming "happy path" scenarios always occur
- Unhandled undefined states - systems failing when in unexpected states
- Null/undefined access - accessing properties on null or undefined objects
- Uninitialized variable usage - using variables before they're properly initialized
- Missing default values - functions without proper parameter defaults
- State transition gaps - missing validation between state changes
- Invalid configuration handling - code failing when config values are missing or malformed
- Missing includes

### **Off-by-One Errors**
- Array bounds mistakes (accessing element [n] in array of size n)
- Loop iteration errors
- Buffer overflow vulnerabilities
- String length miscalculations - incorrect character counting with Unicode
- Negative index access - using negative array indices without validation
- Slice/substring errors - incorrect start/end parameters causing unexpected results
- Iterator boundary issues - for-loops going one step too far or stopping too early
- Writing past array boundaries
- Not validating input sizes
- String manipulation without bounds checking

### **Memory & Resource Management**

#### **Memory Leaks**
- Allocating memory without freeing it
- Losing references to allocated objects
- Circular references preventing garbage collection
- Event listeners not removed on component unmount
- Unclosed file handles, database connections, or network sockets
- Timer/interval functions not cleared

#### **Buffer Overflows**
- Writing past array boundaries
- Not validating input sizes
- String manipulation without bounds checking

#### **Resource Leaks**
- Not closing files, network connections, or database handles
- Holding locks too long
- Not releasing hardware resources
- Audio contexts not closed after use
- Infinite resource allocation - unbounded arrays, maps, or caches that grow indefinitely

### **Faulty Error Handling**

#### **Ignoring Error Conditions**
- Not checking return values
- Assuming operations always succeed
- Silent failures that cascade into larger problems
- Ignored error conditions - not checking return values or response status
- Silent failures - operations failing without notification, logging, or user feedback
- Uncaught promise rejections - async operations without proper .catch() or try/catch

#### **Poor Exception Handling**
- Catching exceptions too broadly
- Not logging error details
- Swallowing exceptions without proper handling
- Broad exception catching - using catch(e) {} without specific error handling
- Missing error logging - critical failures not recorded for debugging
- Error message exposure - sensitive system information leaked in error responses
- Cascading failure points - single failures bringing down entire system components

### **Design Flaws**

#### **Tight Coupling**
- Components that are too dependent on each other
- Functions or settings that should not load before the user has logged in
- Hard to test or modify individual parts
- Changes in one area break seemingly unrelated code
- Hard-to-test code - functions impossible to unit test due to dependencies

#### **Copy-Paste Programming**
- Duplicating code instead of creating reusable functions
- Inconsistent behavior across similar code sections
- Maintenance nightmares when changes are needed
- God objects/functions - single components handling too many responsibilities
- Hardcoded values - magic numbers, URLs, or configuration embedded in code
- Circular dependencies - modules importing each other in a loop
- Missing dependency injection - direct instantiation preventing mocking/testing

#### **Premature Optimization**
- Optimizing code before understanding performance bottlenecks
- Making code complex for marginal performance gains
- Sacrificing readability for questionable speed improvements
- Wrongly addressed properties

### **Missing Calls, Wrong Functions**
- Missing function calls - required operations not being executed
- Wrong function usage - using incorrect APIs or deprecated methods
- Callback hell - deeply nested callbacks instead of Promises/async-await
- Missing function parameters - required arguments not passed to functions
- Function side effects - pure functions that modify global state
- Inconsistent return types - functions returning different types in different scenarios

### **Email Functions Not Being Logged**
- Email functions not logged - email operations without audit trails
- Missing API call logging - external service calls without request/response logging
- Unmonitored critical operations - user authentication, payments, data changes without logs
- Missing error context - log entries without sufficient debugging information
- Sensitive data in logs - passwords, tokens, or PII appearing in log files
- Log level inconsistencies - critical errors logged as warnings or info

### **Non-Existing Tables**
- Non-existing table references - queries against tables that don't exist
- Missing database migrations - schema changes not properly versioned
- SQL injection vulnerabilities - direct string concatenation in queries
- Missing transaction management - data operations without proper ACID compliance
- Connection pool exhaustion - database connections not properly returned to pool
- Missing foreign key constraints - related data without referential integrity
- Unoptimized queries - N+1 query problems or missing indexes

### **Incomplete CSRF Validation**
- Incomplete CSRF validation - state-changing operations without CSRF token verification
- Input validation failures - user input not sanitized before processing
- XSS attack vectors - unescaped user content rendered in HTML
- Authentication bypasses - protected routes accessible without proper authentication
- Session management flaws - sessions not properly invalidated or secured
- Information disclosure - sensitive data exposed in API responses or client code
- Weak password policies - missing complexity requirements or secure storage
- Missing Content Security Policy - no CSP headers preventing code injection

### **Input/Output Issues**

#### **Input Validation Failures**
- Trusting user input without validation
- Not sanitizing data before processing
- SQL injection and similar attack vectors
- Data type mismatches - expecting strings but receiving numbers or vice versa
- Missing input sanitization - user data stored without cleaning
- Stale data display - UI showing outdated information
- Concurrent edit conflicts - multiple users editing same data without conflict resolution
- Missing data validation - server accepting invalid data formats
- Inconsistent data formats - different date formats, number formats across the system

#### **Code Duplication**
- Assuming operations complete in expected timeframes
- Not handling timeouts properly
- Race conditions in timing-sensitive code
- Operations without timeouts - network requests or database queries that can hang indefinitely
- Race conditions in timing - code depending on specific timing that may vary
- Missing debouncing - user input events firing too frequently
- Incorrect setTimeout/setInterval usage - timers not cleared properly
- Synchronous operations blocking UI - long-running tasks freezing the interface
- Missing loading states - users not informed about ongoing operations

### **Additional Critical Issues**
- Uncaught JavaScript errors - runtime errors not handled gracefully
- Memory leaks in SPAs - components not cleaning up when unmounted
- Missing progressive enhancement - core functionality requiring JavaScript
- Accessibility violations - missing ARIA labels, keyboard navigation, or screen reader support
- Performance issues - unnecessary re-renders, large bundle sizes, or blocking operations
- Missing methods
- Hard coded IP addresses

### **Performance & Scalability Issues**
- N+1 query problems - individual database queries in loops
- Unnecessary re-computations - expensive calculations repeated unnecessarily
- Memory usage spikes - operations causing sudden memory consumption increases
- Bundle size bloat - importing entire libraries for single functions
- Blocking main thread - heavy computations preventing UI responsiveness
- Missing caching - repeated expensive operations without result caching
- Resource loading inefficiencies - sequential loading of independent resources

### **Testing & Quality Assurance Gaps**
- Critical paths without tests - core functionality not covered by automated tests
- Flaky tests - tests that pass/fail inconsistently
- Missing integration tests - components not tested together
- Hardcoded test data - tests dependent on specific database states
- Missing error scenario tests - only happy paths tested
- Inadequate mock coverage - external dependencies not properly mocked

### **Codebase Cleanliness**
- **NO redundant or obsolete files in the code base**

---

## **MANDATORY PRE-COMMIT CHECKLIST!**

### **Before Any Code Push:**

1. **If there are no errors** - check that nothing is broken by running tests
2. **If those tests pass** - only then can developers push improvements to GitHub
3. **NO EXCEPTIONS** - All code must pass comprehensive testing before submission

### **Testing Requirements:**
- All unit tests must pass
- Integration tests must pass
- Performance tests must pass
- Security tests must pass
- No linting errors
- No compilation warnings
- No memory leaks detected
- No race conditions identified

---

## **ENFORCEMENT**

**These rules are NON-NEGOTIABLE.**
**Code that violates these standards will be rejected.**
**No exceptions.**
**No compromises.**
**Quality is mandatory.**

---

*This document serves as the definitive guide for all development work on FGCom-mumble. Every line of code must adhere to these standards.*
