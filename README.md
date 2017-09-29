```
 ____  _____    _    ____  __  __ _____ 
|  _ \| ____|  / \  |  _ \|  \/  | ____|
| |_) |  _|   / _ \ | | | | |\/| |  _|  
|  _ <| |___ / ___ \| |_| | |  | | |___ 
|_| \_\_____/_/   \_\____/|_|  |_|_____|

```

The contents of the assembly source file should be enclosed in
parentheses.

Comments may be included, and must be prefixed with semicolons.

This script should work fine with CLISP, SBCL, or CCL implementations
of Common Lisp.

Numerical literals are base-10, by default. Prefix with '#x' for
hexadecimal.

Literal strings may be used as arguments to the PUSH operations.
They will be converted to bytes, via ASCII encoding. Strings used
in this way should not be more than 32 bytes long.

Generic PUSH operations are supported, without an explicit length
suffix. If no length suffix is given, it will be calculated as

  (1) `(min 32 (ash (ceiling (log ARGUMENT 2)) -3))`
if the argument is an integer, or

  (2) `(min 32 (length ARGUMENT))`
if the argument is a string.

"GOTO labels" are supported, as arbitrary symbols preceded by a colon,
`:like_so.` When processed, they will be replaced with `JUMPDEST` instructions,
and references to them will be dereferenced to the corresponding position
in the code. Note that JUMP does not take a literal argument, but draws
its argument, instead, from the stack, so instead of `JUMP :foo`, use
```
  PUSH :foo
  JUMP
```

```
Usage: evmasm.lisp <src> [-o out] [-d|-a]
Options:
-o <out>  designate output path
-d        disassemble
-a        assemble [default]
```