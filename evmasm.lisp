#! /usr/bin/sbcl --script

(defparameter *tmp-read-base* *read-base*)
(setq *read-base* #x10)

(defun word->bytes (word size)
  (loop for i from (1- size) downto 0 collect
		  (ldb (byte 8 (* i 8)) word)))

(defun opseq (lo hi prefix)
  (loop for i from 1 to (1+ (- hi lo)) collect
       (cons (intern (format nil "~A~D" prefix i))
	     (+ (1- lo) i))))

(defparameter *mnemonic->bytecode*
  `((stop   . 00) ;; halts execution
    (add    . 01) ;; addition
    (mul    . 02) ;; multiplication
    (sub    . 03) ;; subtraction
    (div    . 04) ;; integer division (zero safe)
    (sdiv   . 05) ;; signed integer division (zero safe)
    (mod    . 06) ;; modulo remainder (zero safe)
    (smod   . 07) ;; signed modulo remainder (zero safe)
    (addmod . 08) ;; s[0] = 0 if s[2] == 0, else (s[0] + s[1]) mod s[2] 
    (mulmod . 09) ;; (zero safe)
    (exp    . 0a) ;; exponential. s[0]^s[1]
    (signextend . 0b) ;; extend length of 2's comp signed int.
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; Comparison and bitwise logic ;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    (lt . 10)  ;; less-than
    (gt . 11)  ;; greater-than
    (slt . 12) ;; signed less-than
    (sgt . 13) ;; signed greater-than
    (eq . 14)  ;; equality
    (iszero . 15) ;; iszero ("a simple not operator")
    (and . 16) ;; bitwise and
    (or . 17)  ;; bitwise or
    (xor . 18) ;; bitwise xor
    (not . 19) ;; bitwise not
    (byte . 1a) ;; get s[0]th byte from word at s[1], 0 if !(0<=s[0]<32)
    ;;;;;;;;;;
    ;; SHA3 ;;
    ;;;;;;;;;;
    (sha3 . 20) ;; compute keccak-256 hash
    ;;;;;;;;;;;;;;;;;;;;;;;;
    ;; Environmental info ;;
    ;;;;;;;;;;;;;;;;;;;;;;;;
    (address . 30) ;; get addr of currently executing account
    (balance . 31) ;; get balance of given account
    (origin . 32)  ;; get execution origination address
    (caller . 33) ;; get caller address
    (callvalue . 34) ;; get deposited value by inst/trans. resp for exec
    (calldataload . 35) ;; get input data of current env
    (calldatasize . 36) ;; get size of input data in current env
    (calldatacopy . 37) ;; copy input data in current env to mem
    (codesize . 38) ;; get size of code running in current env
    (codecopy . 39) ;; copy code running in current env to memory
    (gasprice . 3a) ;; get price of gas in current env
    (extcodesize . 3b) ;; get size of account's code
    (extcodecopy . 3c) ;; copy an account's code to mem
    ;;;;;;;;;;;;;;;;;;;;;;;
    ;; Block information ;;
    ;;;;;;;;;;;;;;;;;;;;;;;
    (blockhash . 40) ;; get hash of a recent complete block
    (coinbase . 41)  ;; get block's beneficiary address
    (timestamp . 42) ;; get block's timestamp
    (number . 43)    ;; get block's number
    (difficulty . 44) ;; get block's difficulty
    (gaslimit . 45)  ;; get block's gas limit
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; Stack, Memory, Storage, and Flow ;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    (pop . 50) ;; remove item from stack
    (mload . 51) ;; load word from memory
    (mstore . 52) ;; save word to memory
    (mstore8 . 53) ;; save byte to memory
    (sload . 54) ;; load word from storage
    (sstore . 55) ;; save word to storage
    (jump . 56) ;; set pc to s[0]
    (jumpi . 57) ;; set pc to s[0] if s[1] != 0, else pc ++
    (pc . 58) ;; push pc onto stack
    (msize . 59) ;; get size of active memory in bytes
    (gas . 5a) ;; get amount of available gas, after this inst
    (jumpdest . 5b) ;; mark a valid dest for jumps.
    ;;;;;;;;;;;;;;;;;;;;;
    ;; 60 - 7f: Push operations ;;
    ;;;;;;;;;;;;;;;;;;;;;
    ,@(opseq 60 7f 'push)
    ;;;;;;;;;;;;;;;;;;;;;
    ;; 80 - 8f: Dup operations
    ;;;;;;;;;;;;;;;;;;;;;;;
    ,@(opseq 80 8f 'dup)
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; 90 - 9f: exchange operations
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ,@(opseq 90 9f 'swap)
    ;;;;;
    ;; log ops
    ;;;;;
    ,@(opseq a0 a4 'log)
    ;;;;;
    ;; system operations
    ;;;;;
    (create . f0) ;; create new account with associated code
    (call . f1)   ;; message call into an account
    (callcode . f2) ;; message call into account with alt acct's code
    (ret . f3) ;; halt exec returning output data (note name change)
    (delegatecall . f4) ;;
    (invalid . fe) ;; invalid inst
    (selfdestruct . ff) ;; halt execution and register acct for deletion
    ))
    

(defun push-p (symb)
  (when (symbolp symb)
    (let ((name (symbol-name symb)))
      (> (length name) 4)
      (string= (subseq name 0 4) "PUSH"))))

(defun push-bytes (symb)
  (when (push-p symb)
    (read-from-string (subseq (symbol-name symb) 4))))

(defun assemble (code)
  (let ((state 'op)
	(spit-bytes 0)
	(bytes ()))
    (loop for tok in code do
	 (case state
	   ((op)
	    (when (push-p tok)
	      (setq state 'num)
	      (setq spit-bytes (push-bytes tok)))
	    (push (cdr (assoc tok *mnemonic->bytecode*)) bytes))
	   ((num)
	    (setq state 'op)
	    (mapc (lambda (x) (push x bytes))
		  (word->bytes tok spit-bytes)))))
    (reverse bytes)))

(defun assemble-from-file (path)
  (with-open-file (s path :direction :input)
    (assemble (read s :eof-error nil))))

(defun write-bytecode-to-file (path bytecode)
  (with-open-file (s path
		     :if-exists :overwrite
		     :direction :output
		     :element-type '(unsigned-byte 8))
    (loop for byte in bytecode do
	 (write-byte byte s))))

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
			  

(setq *read-base* *tmp-read-base*)
