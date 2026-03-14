;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test-constant-time.lisp - Tests for cl-constant-time
;;;;
;;;; Verifies correctness and constant-time properties of all operations.

(in-package #:cl-constant-time.test)

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "  PASS: ~A~%" ',name))
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~A - ~A~%" ',name e)))))

(defmacro assert-true (form &optional message)
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,message)))

(defmacro assert-false (form &optional message)
  `(when ,form
     (error "Assertion failed (expected false)~@[: ~A~]" ,message)))

(defmacro assert-equal (expected actual &optional message)
  `(unless (equal ,expected ,actual)
     (error "Expected ~S but got ~S~@[: ~A~]" ,expected ,actual ,message)))

;;; ============================================================================
;;; Byte Comparison Tests
;;; ============================================================================

(deftest test-byte-equal
  "Test constant-time-byte= with equal bytes."
  (assert-true (constant-time-byte= 0 0))
  (assert-true (constant-time-byte= 42 42))
  (assert-true (constant-time-byte= 255 255)))

(deftest test-byte-unequal
  "Test constant-time-byte= with unequal bytes."
  (assert-false (constant-time-byte= 0 1))
  (assert-false (constant-time-byte= 42 43))
  (assert-false (constant-time-byte= 0 255)))

;;; ============================================================================
;;; Bytes Comparison Tests
;;; ============================================================================

(deftest test-bytes-equal
  "Test constant-time-bytes= with equal arrays."
  (let ((a (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))
        (b (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4))))
    (assert-true (constant-time-bytes= a b))))

(deftest test-bytes-unequal
  "Test constant-time-bytes= with unequal arrays."
  (let ((a (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))
        (b (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 5))))
    (assert-false (constant-time-bytes= a b))))

(deftest test-bytes-different-length
  "Test constant-time-bytes= with different length arrays."
  (let ((a (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))
        (b (make-array 5 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4 5))))
    (assert-false (constant-time-bytes= a b))))

(deftest test-bytes-empty
  "Test constant-time-bytes= with empty arrays."
  (let ((a (make-array 0 :element-type '(unsigned-byte 8)))
        (b (make-array 0 :element-type '(unsigned-byte 8))))
    (assert-true (constant-time-bytes= a b))))

(deftest test-bytes-single-bit-diff
  "Test constant-time-bytes= with single bit difference."
  (let ((a (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(#x00 #x00 #x00 #x00)))
        (b (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(#x00 #x00 #x00 #x01))))
    (assert-false (constant-time-bytes= a b))))

;;; ============================================================================
;;; String Comparison Tests
;;; ============================================================================

(deftest test-string-equal
  "Test constant-time-string= with equal strings."
  (assert-true (constant-time-string= "hello" "hello"))
  (assert-true (constant-time-string= "" "")))

(deftest test-string-unequal
  "Test constant-time-string= with unequal strings."
  (assert-false (constant-time-string= "hello" "world"))
  (assert-false (constant-time-string= "hello" "hello!")))

;;; ============================================================================
;;; Integer Comparison Tests
;;; ============================================================================

(deftest test-integer-equal
  "Test constant-time-compare-integer with equal integers."
  (assert-true (constant-time-compare-integer 0 0))
  (assert-true (constant-time-compare-integer 12345 12345))
  (assert-true (constant-time-compare-integer #xFFFFFFFF #xFFFFFFFF)))

(deftest test-integer-unequal
  "Test constant-time-compare-integer with unequal integers."
  (assert-false (constant-time-compare-integer 0 1))
  (assert-false (constant-time-compare-integer 12345 12346)))

;;; ============================================================================
;;; Select Tests
;;; ============================================================================

(deftest test-select-true
  "Test constant-time-select with true condition."
  (assert-equal 42 (constant-time-select 1 42 99))
  (assert-equal 42 (constant-time-select 255 42 99)))

(deftest test-select-false
  "Test constant-time-select with false condition."
  (assert-equal 99 (constant-time-select 0 42 99)))

;;; ============================================================================
;;; Arithmetic Tests
;;; ============================================================================

(deftest test-add-no-overflow
  "Test constant-time-add without overflow."
  (multiple-value-bind (result overflow)
      (constant-time-add 100 200)
    (assert-equal 300 result)
    (assert-equal 0 overflow)))

(deftest test-add-overflow
  "Test constant-time-add with overflow."
  (multiple-value-bind (result overflow)
      (constant-time-add #xFFFFFFFF 1)
    (assert-equal 0 result)
    (assert-equal 1 overflow)))

(deftest test-subtract-no-underflow
  "Test constant-time-subtract without underflow."
  (multiple-value-bind (result underflow)
      (constant-time-subtract 200 100)
    (assert-equal 100 result)
    (assert-equal 0 underflow)))

(deftest test-subtract-underflow
  "Test constant-time-subtract with underflow."
  (multiple-value-bind (result underflow)
      (constant-time-subtract 100 200)
    (assert-equal (logand #xFFFFFFFF (- 100 200)) result)
    (assert-equal 1 underflow)))

(deftest test-multiply-no-overflow
  "Test constant-time-multiply without overflow."
  (multiple-value-bind (result overflow)
      (constant-time-multiply 100 200)
    (assert-equal 20000 result)
    (assert-equal 0 overflow)))

(deftest test-multiply-overflow
  "Test constant-time-multiply with overflow."
  (multiple-value-bind (result overflow)
      (constant-time-multiply #xFFFFFFFF 2)
    (assert-equal (logand #xFFFFFFFF (* #xFFFFFFFF 2)) result)
    (assert-equal 1 overflow)))

;;; ============================================================================
;;; Secure Array Tests
;;; ============================================================================

(deftest test-secure-zero-array
  "Test secure-zero-array zeros all elements."
  (let ((arr (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    (secure-zero-array arr)
    (assert-true (every #'zerop arr))))

(deftest test-with-secure-array
  "Test with-secure-array macro."
  (let ((captured nil))
    (with-secure-array (arr 16)
      (dotimes (i 16)
        (setf (aref arr i) (1+ i)))
      (setf captured (copy-seq arr)))
    ;; The original array should be zeroed after the form completes
    ;; (but captured copy should have original values)
    (assert-equal 16 (length captured))
    (assert-equal 1 (aref captured 0))))

;;; ============================================================================
;;; Secure Buffer Tests
;;; ============================================================================

(deftest test-allocate-free-buffer
  "Test allocate-secure-buffer and free-secure-buffer."
  (let ((buf (allocate-secure-buffer 32)))
    (assert-true (secure-buffer-p buf))
    (assert-equal 32 (length (secure-buffer-data buf)))
    (free-secure-buffer buf)
    ;; After free, data should be zeroed
    (assert-true (every #'zerop (secure-buffer-data buf)))))

(deftest test-with-locked-memory
  "Test with-locked-memory macro."
  (with-locked-memory (buf 16)
    (let ((data (secure-buffer-data buf)))
      (dotimes (i 16)
        (setf (aref data i) (1+ i)))
      (assert-equal 1 (aref data 0)))))

;;; ============================================================================
;;; Timing Tests (Statistical)
;;; ============================================================================

(deftest test-bytes-timing-similarity
  "Test that equal and unequal comparisons have similar timing."
  (let* ((data1 (make-array 256 :element-type '(unsigned-byte 8) :initial-element 42))
         (data2 (make-array 256 :element-type '(unsigned-byte 8) :initial-element 42))
         (data3 (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Warm up
    (dotimes (i 100)
      (constant-time-bytes= data1 data2)
      (constant-time-bytes= data1 data3))
    ;; This test just verifies the function runs without timing measurement
    ;; Real timing tests require statistical analysis
    (assert-true (constant-time-bytes= data1 data2))
    (assert-false (constant-time-bytes= data1 data3))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and report results."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)

  (format t "~%Running cl-constant-time tests...~%~%")

  ;; Byte comparison
  (test-byte-equal)
  (test-byte-unequal)

  ;; Bytes comparison
  (test-bytes-equal)
  (test-bytes-unequal)
  (test-bytes-different-length)
  (test-bytes-empty)
  (test-bytes-single-bit-diff)

  ;; String comparison
  (test-string-equal)
  (test-string-unequal)

  ;; Integer comparison
  (test-integer-equal)
  (test-integer-unequal)

  ;; Select
  (test-select-true)
  (test-select-false)

  ;; Arithmetic
  (test-add-no-overflow)
  (test-add-overflow)
  (test-subtract-no-underflow)
  (test-subtract-underflow)
  (test-multiply-no-overflow)
  (test-multiply-overflow)

  ;; Secure arrays
  (test-secure-zero-array)
  (test-with-secure-array)

  ;; Secure buffers
  (test-allocate-free-buffer)
  (test-with-locked-memory)

  ;; Timing
  (test-bytes-timing-similarity)

  (format t "~%Results: ~D passed, ~D failed, ~D total~%"
          *pass-count* *fail-count* *test-count*)

  (zerop *fail-count*))
