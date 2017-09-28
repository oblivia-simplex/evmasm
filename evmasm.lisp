#! /usr/bin/sbcl --script

;(defparameter *tmp-read-base* *read-base*)
;(setq *read-base* #x10)
;(setq *print-base* *read-base*)

(defun word->bytes (word size)
  (loop for i from (1- size) downto 0 collect
		  (ldb (byte 8 (* i 8)) word)))

(defun opseq (lo hi prefix)
  (loop for i from 1 to (1+ (- hi lo)) collect
       (cons (intern (format nil "~A~D" prefix i))
	     (+ (1- lo) i))))

(defparameter *mnemonic->bytecode*
  `((stop   . #x00) ;; halts execution
    (add    . #x01) ;; addition
    (mul    . #x02) ;; multiplication
    (sub    . #x03) ;; subtraction
    (div    . #x04) ;; integer division (zero safe)
    (sdiv   . #x05) ;; signed integer division (zero safe)
    (mod    . #x06) ;; modulo remainder (zero safe)
    (smod   . #x07) ;; signed modulo remainder (zero safe)
    (addmod . #x08) ;; s[0] = 0 if s[2] == 0, else (s[0] + s[1]) mod s[2] 
    (mulmod . #x09) ;; (zero safe)
    (exp    . #x0a) ;; exponential. s[0]^s[1]
    (signextend . #x0b) ;; extend length of 2's comp signed int.
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; Comparison and bitwise logic ;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    (lt . #x10)  ;; less-than
    (gt . #x11)  ;; greater-than
    (slt . #x12) ;; signed less-than
    (sgt . #x13) ;; signed greater-than
    (eq . #x14)  ;; equality
    (iszero . #x15) ;; iszero ("a simple not operator")
    (and . #x16) ;; bitwise and
    (or . #x17)  ;; bitwise or
    (xor . #x18) ;; bitwise xor
    (not . #x19) ;; bitwise not
    (byte . #x1a) ;; get s[0]th byte from word at s[1], 0 if !(0<=s[0]<32)
    ;;;;;;;;;;
    ;; SHA3 ;;
    ;;;;;;;;;;
    (sha3 . #x20) ;; compute keccak-256 hash
    ;;;;;;;;;;;;;;;;;;;;;;;;
    ;; Environmental info ;;
    ;;;;;;;;;;;;;;;;;;;;;;;;
    (address . #x30) ;; get addr of currently executing account
    (balance . #x31) ;; get balance of given account
    (origin . #x32)  ;; get execution origination address
    (caller . #x33) ;; get caller address
    (callvalue . #x34) ;; get deposited value by inst/trans. resp for exec
    (calldataload . #x35) ;; get input data of current env
    (calldatasize . #x36) ;; get size of input data in current env
    (calldatacopy . #x37) ;; copy input data in current env to mem
    (codesize . #x38) ;; get size of code running in current env
    (codecopy . #x39) ;; copy code running in current env to memory
    (gasprice . #x3a) ;; get price of gas in current env
    (extcodesize . #x3b) ;; get size of account's code
    (extcodecopy . #x3c) ;; copy an account's code to mem
    ;;;;;;;;;;;;;;;;;;;;;;;
    ;; Block information ;;
    ;;;;;;;;;;;;;;;;;;;;;;;
    (blockhash . #x40) ;; get hash of a recent complete block
    (coinbase . #x41)  ;; get block's beneficiary address
    (timestamp . #x42) ;; get block's timestamp
    (number . #x43)    ;; get block's number
    (difficulty . #x44) ;; get block's difficulty
    (gaslimit . #x45)  ;; get block's gas limit
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; Stack, Memory, Storage, and Flow ;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    (pop . #x50) ;; remove item from stack
    (mload . #x51) ;; load word from memory
    (mstore . #x52) ;; save word to memory
    (mstore8 . #x53) ;; save byte to memory
    (sload . #x54) ;; load word from storage
    (sstore . #x55) ;; save word to storage
    (jump . #x56) ;; set pc to s[0]
    (jumpi . #x57) ;; set pc to s[0] if s[1] != 0, else pc ++
    (pc . #x58) ;; push pc onto stack
    (msize . #x59) ;; get size of active memory in bytes
    (gas . #x5a) ;; get amount of available gas, after this inst
    (jumpdest . #x5b) ;; mark a valid dest for jumps.
    ;;;;;;;;;;;;;;;;;;;;;
    ;; 60 - 7f: Push operations ;;
    ;;;;;;;;;;;;;;;;;;;;;
    ,@(opseq #x60 #x7f 'push)
    ;;;;;;;;;;;;;;;;;;;;;
    ;; 80 - 8f: Dup operations
    ;;;;;;;;;;;;;;;;;;;;;;;
    ,@(opseq #x80 #x8f 'dup)
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; 90 - 9f: exchange operations
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ,@(opseq #x90 #x9f 'swap)
    ;;;;;
    ;; log ops
    ;;;;;
    ,@(opseq #xa0 #xa4 'log)
    ;;;;;
    ;; system operations
    ;;;;;
    (create . #xf0) ;; create new account with associated code
    (call . #xf1)   ;; message call into an account
    (callcode . #xf2) ;; message call into account with alt acct's code
    (return . #xf3) ;; halt exec returning output data (note name change)
    (delegatecall . #xf4) ;;
    (invalid . #xfe) ;; invalid inst
    (selfdestruct . #xff) ;; halt execution and register acct for deletion
    ))
    

(defun push-p (symb)
  (when (symbolp symb)
    (let ((name (symbol-name symb)))
      (and (> (length name) 4)
	   (string= (subseq name 0 4) "PUSH")))))

(defun push-bytes (symb)
  (read-from-string (subseq (symbol-name symb) 4)))

(defun assemble (code)
  (let ((state 'op)
	(spit-bytes 0)
	(bytes ()))
    (loop for tok in code do
	 (case state
	   ((op)
	    (assert (not (numberp tok)))
	    (when (push-p tok)
	      (setq state 'num)
	      (setq spit-bytes (push-bytes tok)))
	    (push (cdr (assoc tok *mnemonic->bytecode*)) bytes))
	   ((num)
	    (assert (numberp tok))
	    (setq state 'op)
	    (mapc (lambda (x) (push x bytes))
		  (word->bytes tok spit-bytes)))))
    (reverse bytes)))

(defun assemble-from-file (path)
  (with-open-file (s path :direction :input)
    (assemble (read s :eof-error nil))))

(defun write-bytecode-to-file (path bytecode &key (verbose t))
  (let ((i 0))
    (with-open-file (s path
		       :if-exists :overwrite
		       :if-does-not-exist :create
		       :direction :output
		       :element-type '(unsigned-byte 8))
      (loop for byte in bytecode do
	   (incf i)
	   (when verbose
	     (format t "~2X~A" byte
		     (if (zerop (mod i #x10)) #\Newline #\Space)))
	   (write-byte byte s)))
    (format t "~%#x~X bytes written to ~A~%" i path)))

(defun main (args)
  (let ((src (cadr args))
	(dst (caddr args)))
    (cond ((= (length args) 2)
	   (setq dst (concatenate 'string src ".out")))
	  ((< (length args) 2)
	   (format t "Usage: ~A <src> [out]~%" (car args))
	   (quit)))
    (write-bytecode-to-file dst (assemble-from-file src))))


(defparameter *argv*
  #+sbcl
  sb-ext:*posix-argv*
  #+clisp
  (cons "evmasm.lisp" *args*)
  #+ccl
  ccl:*command-line-argument-list*)

(main *argv*)
			  

;(setq *read-base* *tmp-read-base*)
;(setq *print-base* *read-base*)
