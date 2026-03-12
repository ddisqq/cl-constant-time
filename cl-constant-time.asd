;;;; cl-constant-time.asd - Timing-safe cryptographic operations
;;;;
;;;; Pure Common Lisp library for constant-time operations that resist
;;;; timing side-channel attacks. No external dependencies.

(asdf:defsystem #:cl-constant-time
  :description "Timing-safe cryptographic operations for Common Lisp"
  :author "Parkian Company LLC"
  :license "MIT"
  :version "1.0.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :components ((:file "constant-time"))))
  :in-order-to ((test-op (test-op #:cl-constant-time/test))))

(asdf:defsystem #:cl-constant-time/test
  :description "Tests for cl-constant-time"
  :depends-on (#:cl-constant-time)
  :serial t
  :components ((:module "test"
                :components ((:file "test-constant-time"))))
  :perform (test-op (o c)
                    (let ((result (uiop:symbol-call :cl-constant-time.test :run-tests)))
                      (unless result
                        (error "Tests failed")))))
