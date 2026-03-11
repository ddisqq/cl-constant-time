# cl-constant-time

Timing-safe cryptographic operations for Common Lisp.

## Overview

This library provides constant-time comparison and arithmetic operations that resist timing side-channel attacks. All functions execute in time dependent only on data length, not content, protecting against attacks that measure execution time to infer secret values.

## Features

- **Constant-time comparison**: Byte arrays, strings, and integers
- **Branchless selection**: Conditional operations without branches
- **Overflow-detecting arithmetic**: Addition, subtraction, multiplication
- **Secure memory**: Buffer allocation and zeroing
- **Pure Common Lisp**: No external dependencies

## Installation

Clone the repository and load via ASDF:

```lisp
(asdf:load-system :cl-constant-time)
```

## Usage

### Byte Array Comparison

```lisp
(use-package :cl-constant-time)

;; SAFE - constant time
(constant-time-bytes= computed-mac expected-mac)

;; UNSAFE - timing leak!
(equalp computed-mac expected-mac)
```

### String Comparison

```lisp
;; Password verification (constant-time)
(constant-time-string= entered-password stored-hash)
```

### Conditional Selection (Branchless)

```lisp
;; Returns true-value if condition is non-zero, false-value otherwise
;; No branching instructions - timing independent of condition
(constant-time-select condition true-value false-value)
```

### Arithmetic with Overflow Detection

```lisp
;; Returns (values result overflow-flag)
(constant-time-add a b)
(constant-time-subtract a b)
(constant-time-multiply a b)
```

### Secure Memory

```lisp
;; Automatically zeroed on scope exit
(with-secure-array (key 32)
  ;; use key for cryptographic operations
  ...)

;; Manual zeroing
(secure-zero-array secret-data)
```

## API Reference

### Comparison Functions

| Function | Description |
|----------|-------------|
| `constant-time-byte=` | Compare two bytes |
| `constant-time-bytes=` | Compare two byte arrays |
| `constant-time-string=` | Compare two strings (UTF-8) |
| `constant-time-compare-integer` | Compare two integers |

### Selection and Array Operations

| Function | Description |
|----------|-------------|
| `constant-time-select` | Branchless conditional selection |
| `constant-time-aref` | Timing-safe array access |
| `constant-time-move-conditional` | Conditional memory copy |

### Arithmetic

| Function | Description |
|----------|-------------|
| `constant-time-add` | Addition with overflow flag |
| `constant-time-subtract` | Subtraction with underflow flag |
| `constant-time-multiply` | Multiplication with overflow flag |

### Memory Operations

| Function | Description |
|----------|-------------|
| `secure-zero-array` | Zero array resisting optimization |
| `with-secure-array` | Scoped secure array with auto-zero |
| `allocate-secure-buffer` | Allocate secure buffer |
| `free-secure-buffer` | Zero and free secure buffer |
| `with-locked-memory` | Scoped secure buffer |

### SBCL-Specific

| Function | Description |
|----------|-------------|
| `constant-time-memory-compare` | Compare raw memory regions |
| `constant-time-zero-memory` | Zero raw memory |
| `constant-time-copy-memory` | Copy raw memory |

## Standards Compliance

This implementation follows NIST guidelines for timing-attack resistance:

- **NIST SP 800-56A Rev.3**: Key-Agreement Output Validation
- **NIST SP 800-56B Rev.2**: Implementation Considerations
- **NIST SP 800-56C Rev.2**: Key-Derivation Methods

## Testing

```lisp
(asdf:test-system :cl-constant-time)
```

Or run tests directly:

```lisp
(cl-constant-time.test:run-tests)
```

## Security Considerations

1. **Never use `equalp` for secret comparison** - it has early-return behavior
2. **Length leaks are unavoidable** - comparing arrays of different lengths returns immediately
3. **Compiler optimizations** - the library uses read-back patterns to prevent optimization
4. **Cache timing** - memory access patterns are designed to be data-independent

## License

MIT License - See LICENSE file.

## Origin

Extracted from the CLPIC (Common Lisp P2P Intellectual Property Chain) project.
