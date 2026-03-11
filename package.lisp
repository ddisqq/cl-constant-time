;;;; package.lisp - Package definition for cl-constant-time
;;;;
;;;; Timing-safe cryptographic operations resistant to side-channel attacks.

(defpackage #:cl-constant-time
  (:use #:cl)
  (:nicknames #:ct)
  (:export
   ;; Comparison functions
   #:constant-time-byte=
   #:constant-time-bytes=
   #:constant-time-string=
   #:constant-time-compare-integer

   ;; Array operations
   #:constant-time-aref
   #:constant-time-select
   #:constant-time-move-conditional

   ;; Arithmetic (with overflow detection)
   #:constant-time-add
   #:constant-time-subtract
   #:constant-time-multiply

   ;; Memory operations
   #:constant-time-memory-compare
   #:constant-time-zero-memory
   #:constant-time-copy-memory
   #:secure-zero-array
   #:with-secure-array

   ;; Secure buffer management
   #:allocate-secure-buffer
   #:free-secure-buffer
   #:with-locked-memory
   #:secure-buffer-data

   ;; Testing utilities
   #:measure-timing-variability
   #:test-constant-time-properties))

(defpackage #:cl-constant-time.test
  (:use #:cl #:cl-constant-time)
  (:export #:run-tests))
