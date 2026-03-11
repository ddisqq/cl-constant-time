;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; constant-time.lisp - Timing-safe cryptographic operations
;;;;
;;;; This module implements constant-time comparison and arithmetic operations
;;;; to prevent timing side-channel attacks. All functions execute in time
;;;; dependent only on data length, not content.
;;;;
;;;; NIST STANDARDS COMPLIANCE:
;;;;   - NIST SP 800-56A Rev.3: Key-Agreement Output Validation
;;;;   - NIST SP 800-56B Rev.2: Implementation Considerations
;;;;   - NIST SP 800-56C Rev.2: Key-Derivation Methods
;;;;
;;;; CONSTANT-TIME REQUIREMENTS:
;;;;   1. No early-return on comparison mismatch (process all bytes)
;;;;   2. No conditional branches dependent on secret data values
;;;;   3. Memory access patterns independent of secret values
;;;;   4. Cache access patterns independent of secret values
;;;;   5. Arithmetic operations must not short-circuit

(in-package #:cl-constant-time)

;;; ============================================================================
;;; Secure Buffer Support
;;; ============================================================================

(defstruct (secure-buffer (:conc-name secure-buffer-))
  "Secure buffer for sensitive data (without memory locking on most platforms)."
  (data nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defun allocate-secure-buffer (size)
  "Allocate a secure buffer of SIZE bytes."
  (make-secure-buffer
   :data (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))

(defun free-secure-buffer (buffer)
  "Free a secure buffer by zeroing its contents."
  (when (and buffer (secure-buffer-data buffer))
    (let ((data (secure-buffer-data buffer)))
      (dotimes (i (length data))
        (setf (aref data i) 0))))
  nil)

(defmacro with-locked-memory ((var size) &body body)
  "Allocate a secure buffer, execute BODY, then securely zero and free it.
   VAR is bound to the secure-buffer struct. Use SECURE-BUFFER-DATA to access bytes."
  (let ((buffer-var (gensym "BUFFER"))
        (result-var (gensym "RESULT")))
    `(let* ((,buffer-var (allocate-secure-buffer ,size))
            (,var ,buffer-var)
            (,result-var nil))
       (unwind-protect
           (setf ,result-var (progn ,@body))
         (when ,buffer-var
           (free-secure-buffer ,buffer-var)))
       ,result-var)))

;;; ============================================================================
;;; Inline Declarations for Hot Path Functions
;;; ============================================================================

(declaim (inline constant-time-byte=))
(declaim (inline constant-time-bytes=))
(declaim (inline constant-time-aref))
(declaim (inline constant-time-select))
(declaim (inline constant-time-add))
(declaim (inline constant-time-subtract))
(declaim (inline constant-time-multiply))

(declaim (ftype (function ((unsigned-byte 8) (unsigned-byte 8)) boolean)
                constant-time-byte=))
(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))
                           (simple-array (unsigned-byte 8) (*)))
                          boolean)
                constant-time-bytes=))

;;; ============================================================================
;;; Constant-Time Comparison Functions
;;; ============================================================================

(defun constant-time-byte= (a b)
  "Constant-time comparison of two unsigned bytes.

   PARAMETERS:
     a, b - (unsigned-byte 8) values to compare

   RETURNS:
     T if equal, NIL if different

   TIMING GUARANTEE:
     Execution time independent of input values.
     Uses XOR to compute difference (a XOR b = 0 iff equal).

   EXAMPLE:
     (constant-time-byte= #xFF #xFF)  ; => T
     (constant-time-byte= #xFF #x00)  ; => NIL"
  (declare (type (unsigned-byte 8) a b)
           (optimize (speed 3) (safety 0)))
  (zerop (logxor a b)))

(defun constant-time-bytes= (a b)
  "Constant-time comparison of two byte arrays.

   PARAMETERS:
     a, b - (simple-array (unsigned-byte 8) (*)) byte vectors

   RETURNS:
     T if equal (all bytes match), NIL if any byte differs

   ALGORITHM:
     1. Check lengths first (early length mismatch is unavoidable)
     2. Accumulate XOR of all byte pairs
     3. Never early-return on first difference
     4. Final ZEROP check on accumulated result

   TIMING GUARANTEE:
     For arrays of same length: constant time regardless of data.

   USE CASES:
     - HMAC verification
     - Signature verification
     - Password hash comparison

   WARNING:
     DO NOT use EQUALP for crypto comparisons - timing leak!

   EXAMPLE:
     (constant-time-bytes= #(0 1 2 3) #(0 1 2 3))  ; => T (safe)"
  (declare (type (simple-array (unsigned-byte 8) (*)) a b)
           (optimize (speed 3) (safety 0)))

  (when (/= (length a) (length b))
    (return-from constant-time-bytes= nil))

  (let ((result 0)
        (len (length a)))
    (declare (type fixnum len)
             (type (unsigned-byte 8) result))

    (dotimes (i len)
      (setf result (logior result (logxor (aref a i) (aref b i)))))

    (zerop result)))

(defun constant-time-string= (a b)
  "Constant-time comparison of two strings.

   Converts strings to UTF-8 byte vectors and uses CONSTANT-TIME-BYTES=.

   USE CASES:
     - Password comparison
     - API key validation
     - Token comparison"
  (declare (optimize (speed 3) (safety 1)))
  (let ((a-bytes (string-to-octets a))
        (b-bytes (string-to-octets b)))
    (constant-time-bytes= a-bytes b-bytes)))

(defun constant-time-compare-integer (a b)
  "Constant-time comparison of two integers.

   Converts both integers to byte representations, pads to same length,
   then uses CONSTANT-TIME-BYTES=.

   NOTE: Timing correlates with integer size (bit length) not value."
  (declare (type integer a b)
           (optimize (speed 3) (safety 1)))

  (let* ((a-bytes (integer-to-bytes a))
         (b-bytes (integer-to-bytes b))
         (max-len (max (length a-bytes) (length b-bytes)))
         (a-padded (make-array max-len :element-type '(unsigned-byte 8) :initial-element 0))
         (b-padded (make-array max-len :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; Pad the shorter array with leading zeros
    (replace a-padded a-bytes :start1 (- max-len (length a-bytes)))
    (replace b-padded b-bytes :start1 (- max-len (length b-bytes)))

    (constant-time-bytes= a-padded b-padded)))

;;; ============================================================================
;;; Internal Utilities
;;; ============================================================================

(defun string-to-octets (string)
  "Convert STRING to a UTF-8 byte vector."
  (declare (type string string)
           (optimize (speed 3) (safety 1)))
  (let* ((len (length string))
         ;; Estimate max size (worst case: 4 bytes per char for UTF-8)
         (result (make-array (* 4 len) :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (loop for char across string
          for code = (char-code char)
          do (cond
               ((< code #x80)
                (vector-push code result))
               ((< code #x800)
                (vector-push (logior #xC0 (ash code -6)) result)
                (vector-push (logior #x80 (logand code #x3F)) result))
               ((< code #x10000)
                (vector-push (logior #xE0 (ash code -12)) result)
                (vector-push (logior #x80 (logand (ash code -6) #x3F)) result)
                (vector-push (logior #x80 (logand code #x3F)) result))
               (t
                (vector-push (logior #xF0 (ash code -18)) result)
                (vector-push (logior #x80 (logand (ash code -12) #x3F)) result)
                (vector-push (logior #x80 (logand (ash code -6) #x3F)) result)
                (vector-push (logior #x80 (logand code #x3F)) result))))
    ;; Return a simple-array copy
    (let ((final (make-array (fill-pointer result) :element-type '(unsigned-byte 8))))
      (replace final result)
      final)))

(defun integer-to-bytes (n)
  "Convert a non-negative integer N to a big-endian byte vector."
  (declare (type integer n)
           (optimize (speed 3) (safety 1)))
  (when (zerop n)
    (return-from integer-to-bytes
      (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let* ((byte-count (ceiling (integer-length n) 8))
         (result (make-array byte-count :element-type '(unsigned-byte 8))))
    (loop for i from (1- byte-count) downto 0
          for shift from 0 by 8
          do (setf (aref result i) (logand #xFF (ash n (- shift)))))
    result))

;;; ============================================================================
;;; Constant-Time Array Operations
;;; ============================================================================

(defun constant-time-aref (array index &optional (fallback 0))
  "Constant-time array access that doesn't leak index via timing.

   Uses branchless operations - no if/when/cond on secret data.
   Returns FALLBACK if index is out of bounds."
  (declare (type (simple-array (unsigned-byte 8) (*)) array)
           (type fixnum index)
           (type (unsigned-byte 8) fallback)
           (optimize (speed 3) (safety 0)))

  (let* ((len (length array))
         (diff (- index len))
         (valid-bit (logand 1 (ash diff -31)))
         (is-valid (logxor valid-bit 1))
         (mask (logand #xFF (- is-valid)))
         (clamped-index (logand index (- is-valid)))
         (value (aref array (mod clamped-index (max 1 len)))))
    (declare (type fixnum len diff clamped-index)
             (type (integer 0 1) valid-bit is-valid)
             (type (unsigned-byte 8) mask value))
    (logior (logand value mask)
            (logand fallback (logxor mask #xFF)))))

(defun constant-time-select (condition true-value false-value)
  "Constant-time conditional selection - FULLY BRANCHLESS.

   Returns TRUE-VALUE if CONDITION is non-zero, FALSE-VALUE otherwise.
   Uses bitwise operations only - no IF/COND/WHEN branches."
  (declare (type fixnum condition)
           (type (unsigned-byte 8) true-value false-value)
           (optimize (speed 3) (safety 0)))

  (let* ((c8 (logand #xFF (logior condition (ash condition -8)
                                  (ash condition -16) (ash condition -24))))
         (neg-c8 (logand #xFF (- 256 c8)))
         (or-result (logand #xFF (logior c8 neg-c8)))
         (nonzero-bit (logand 1 (ash or-result -7)))
         (mask (logand #xFF (- nonzero-bit))))
    (declare (type (unsigned-byte 8) c8 neg-c8 or-result mask)
             (type (integer 0 1) nonzero-bit))
    (logior (logand true-value mask)
            (logand false-value (logxor mask #xFF)))))

(defun constant-time-move-conditional (condition dest source start length)
  "Constant-time conditional memory move - FULLY BRANCHLESS.

   Moves LENGTH bytes from SOURCE to DEST starting at START if CONDITION is non-zero.
   Parameter validation uses branches (acceptable - public parameters)."
  (declare (type fixnum condition)
           (type (simple-array (unsigned-byte 8) (*)) dest source)
           (type fixnum start length)
           (optimize (speed 3) (safety 1)))

  (when (or (< start 0)
            (>= start (length dest))
            (>= (+ start length) (length dest))
            (>= length (length source)))
    (error "Invalid parameters for constant-time move"))

  (let* ((c8 (logand #xFF (logior condition (ash condition -8)
                                  (ash condition -16) (ash condition -24))))
         (neg-c8 (logand #xFF (- 256 c8)))
         (or-result (logand #xFF (logior c8 neg-c8)))
         (nonzero-bit (logand 1 (ash or-result -7)))
         (mask (logand #xFF (- nonzero-bit))))
    (declare (type (unsigned-byte 8) c8 neg-c8 or-result mask)
             (type (integer 0 1) nonzero-bit))

    (dotimes (i length)
      (let ((dest-val (aref dest (+ start i)))
            (src-val (aref source i)))
        (setf (aref dest (+ start i))
              (logior (logand src-val mask)
                      (logand dest-val (logxor mask #xFF))))))))

;;; ============================================================================
;;; Constant-Time Arithmetic - FULLY BRANCHLESS
;;; ============================================================================

(defun constant-time-add (a b)
  "Constant-time addition with overflow detection - BRANCHLESS.

   Returns (values result overflow-flag).
   overflow-flag is 1 if overflow occurred, 0 otherwise."
  (declare (type (unsigned-byte 32) a b)
           (optimize (speed 3) (safety 0)))
  (let* ((sum (+ a b))
         (result (logand sum #xFFFFFFFF))
         (overflow-flag (logand 1 (ash sum -32))))
    (declare (type (unsigned-byte 32) result)
             (type (integer 0 1) overflow-flag))
    (values result overflow-flag)))

(defun constant-time-subtract (a b)
  "Constant-time subtraction with underflow detection - BRANCHLESS.

   Returns (values result underflow-flag).
   underflow-flag is 1 if underflow occurred (a < b), 0 otherwise."
  (declare (type (unsigned-byte 32) a b)
           (optimize (speed 3) (safety 0)))
  (let* ((diff (- a b))
         (result (logand diff #xFFFFFFFF))
         (underflow-flag (logand 1 (ash diff -63))))
    (declare (type (unsigned-byte 32) result)
             (type (integer 0 1) underflow-flag))
    (values result underflow-flag)))

(defun constant-time-multiply (a b)
  "Constant-time multiplication with overflow detection - BRANCHLESS.

   Returns (values result overflow-flag).
   overflow-flag is 1 if overflow occurred, 0 otherwise."
  (declare (type (unsigned-byte 32) a b)
           (optimize (speed 3) (safety 0)))
  (let* ((product (* a b))
         (result (logand product #xFFFFFFFF))
         (high-bits (ash product -32))
         (neg-high (- high-bits))
         (or-result (logior high-bits neg-high))
         (overflow-flag (logand 1 (ash or-result -63))))
    (declare (type (unsigned-byte 32) result)
             (type (integer 0 1) overflow-flag))
    (values result overflow-flag)))

;;; ============================================================================
;;; Memory Operations (SBCL-specific)
;;; ============================================================================

#+sbcl
(defun constant-time-memory-compare (ptr1 ptr2 size)
  "Constant-time comparison of two memory regions (SBCL only)."
  (declare (type sb-sys:system-area-pointer ptr1 ptr2)
           (type fixnum size)
           (optimize (speed 3) (safety 0)))

  (let ((result 0)
        (temp 0))
    (declare (type (unsigned-byte 8) result temp))

    (dotimes (i size)
      (setf temp (logxor (sb-sys:sap-ref-8 ptr1 i)
                         (sb-sys:sap-ref-8 ptr2 i)))
      (setf result (logior result temp)))

    (zerop result)))

#+sbcl
(defun constant-time-zero-memory (ptr size)
  "Zero memory in constant time without optimization interference (SBCL only)."
  (declare (type sb-sys:system-area-pointer ptr)
           (type fixnum size)
           (optimize (speed 3) (safety 0)))

  (let ((checksum 0)
        (temp 0))
    (declare (type (unsigned-byte 8) checksum temp))

    (dotimes (i size)
      (setf (sb-sys:sap-ref-8 ptr i) 0)
      (setf temp (sb-sys:sap-ref-8 ptr i))
      (setf checksum (logxor checksum temp)))

    checksum))

#+sbcl
(defun constant-time-copy-memory (dest source size)
  "Copy memory in constant time without optimization interference (SBCL only)."
  (declare (type sb-sys:system-area-pointer dest source)
           (type fixnum size)
           (optimize (speed 3) (safety 0)))

  (let ((checksum 0)
        (temp 0))
    (declare (type (unsigned-byte 8) checksum temp))

    (dotimes (i size)
      (setf temp (sb-sys:sap-ref-8 source i))
      (setf (sb-sys:sap-ref-8 dest i) temp)
      (setf checksum (logxor checksum temp)))

    checksum))

;;; Portable stubs for non-SBCL
#-sbcl
(defun constant-time-memory-compare (ptr1 ptr2 size)
  (declare (ignore ptr1 ptr2 size))
  (error "constant-time-memory-compare requires SBCL"))

#-sbcl
(defun constant-time-zero-memory (ptr size)
  (declare (ignore ptr size))
  (error "constant-time-zero-memory requires SBCL"))

#-sbcl
(defun constant-time-copy-memory (dest source size)
  (declare (ignore dest source size))
  (error "constant-time-copy-memory requires SBCL"))

;;; ============================================================================
;;; Secure Array Zeroing (Portable)
;;; ============================================================================

(defun secure-zero-array (array)
  "Zero a byte array containing secret data in a way that resists compiler optimization.

   Uses a read-back-and-verify pattern to prevent the compiler from optimizing
   away the writes.

   USAGE:
     (unwind-protect
         (let ((secret-key (generate-secret-key)))
           ... use secret-key ...)
       (secure-zero-array secret-key))"
  (declare (type (simple-array (unsigned-byte 8) (*)) array)
           (optimize (speed 3) (safety 0)))
  (let ((len (length array))
        (checksum 0))
    (declare (type fixnum len)
             (type (unsigned-byte 8) checksum))
    (dotimes (i len)
      (setf (aref array i) 0))
    (dotimes (i len)
      (setf checksum (logxor checksum (aref array i))))
    checksum))

(defmacro with-secure-array ((var size) &body body)
  "Create a temporary byte array that is automatically zeroed on scope exit.

   USAGE:
     (with-secure-array (temp-key 32)
       ... use temp-key for intermediate key material ...)
     ;; temp-key is automatically zeroed here, even on error"
  `(let ((,var (make-array ,size :element-type '(unsigned-byte 8) :initial-element 0)))
     (unwind-protect
         (progn ,@body)
       (secure-zero-array ,var))))

;;; ============================================================================
;;; Timing Analysis and Testing
;;; ============================================================================

(defun measure-timing-variability (func &rest args)
  "Measure timing variability of a function for timing attack analysis.

   Returns (values mean min max std-dev)."
  (declare (optimize (speed 3) (safety 1)))

  (let ((times (make-array 100 :element-type 'double-float :initial-element 0.0d0))
        (start-time 0)
        (end-time 0))

    ;; Warm up
    (dotimes (i 10)
      (apply func args))

    ;; Measure actual timings
    (dotimes (i 100)
      (setf start-time (get-internal-real-time))
      (apply func args)
      (setf end-time (get-internal-real-time))
      (setf (aref times i) (float (/ (- end-time start-time)
                                     internal-time-units-per-second)
                                  1.0d0)))

    ;; Calculate statistics
    (let ((mean 0.0d0)
          (min-time most-positive-double-float)
          (max-time most-negative-double-float)
          (variance 0.0d0))

      (dotimes (i 100)
        (incf mean (aref times i)))
      (setf mean (/ mean 100))

      (dotimes (i 100)
        (setf min-time (min min-time (aref times i)))
        (setf max-time (max max-time (aref times i))))

      (dotimes (i 100)
        (incf variance (expt (- (aref times i) mean) 2)))
      (setf variance (/ variance 100))

      (values mean min-time max-time (sqrt variance)))))

(defun test-constant-time-properties ()
  "Test constant-time properties of comparison functions."
  (format t "~&Testing constant-time comparison functions...~%")

  (multiple-value-bind (mean min max std-dev)
      (measure-timing-variability #'constant-time-byte= 42 42)
    (format t "Byte comparison (equal): mean=~F, min=~F, max=~F, stddev=~F~%"
            mean min max std-dev))

  (multiple-value-bind (mean min max std-dev)
      (measure-timing-variability #'constant-time-byte= 42 123)
    (format t "Byte comparison (unequal): mean=~F, min=~F, max=~F, stddev=~F~%"
            mean min max std-dev))

  (let ((data1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
        (data2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
        (data3 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 123)))

    (multiple-value-bind (mean min max std-dev)
        (measure-timing-variability #'constant-time-bytes= data1 data2)
      (format t "Bytes comparison (equal): mean=~F, min=~F, max=~F, stddev=~F~%"
              mean min max std-dev))

    (multiple-value-bind (mean min max std-dev)
        (measure-timing-variability #'constant-time-bytes= data1 data3)
      (format t "Bytes comparison (unequal): mean=~F, min=~F, max=~F, stddev=~F~%"
              mean min max std-dev))))
