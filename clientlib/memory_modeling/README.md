# Ethereum Memory Modeling

The code in this folder is originating from our OOPSLA20 [paper](https://doi.org/10.1145/3428258) "Precise Static Modeling of Ethereum "Memory"".
An earlier version of this codebase can be found in the peer-reviwed [artifact](https://zenodo.org/record/4059797) of the paper.

This documentation is aimed at helping with the integration of the memory modeling by new client analyses.  
If you wish to contribute fixes or new features the comments in the corresponding files provide deeper insights.  

Client analyses should just include file `memory_modeling.dl`.

## API

#### High-level uses/defs
Arguments in the following relations can have scalar or array types even though they are of type `Variable`.

---
`MemoryStatement_ActualArg(stmt:Statement, actual:Variable, index:number)`

Variable `actual` is the `index`'th arguement of memory reading statement `stmt`.  
There is ongoing work to output a more general type of argument that would also include other memory slices.

Includes results for:  
  - `LOGx` statements:
      The indexed args (1 for `LOG1`, 2 for `LOG2`, etc)
      followed by the ABI encoded actual memory args
  - `CALL` statements have the following args, all followed by the actual memory args:
    - `CALL`: gas, targetAddr, value
    - `STATICCALL`: gas, targetAddr
    - `DELEGATECALL`: gas, targetAddr  
     Note: In high level calls the function selector is the 0th actual memory arg
  - `SHA3`: The actual memory args.
  - `RETURN`: The actual memory args, ABI encoded.
  - `CALLDATALOAD`: The 0th actual arg is the array written to.
  - `MLOAD`: 0th actual arg can be a var that will definately be red from it (that has been stored previously using MSTORE)

---
`ExternalCall_ActualReturn(callStmt:Statement, actual:Variable, index:number)`

Variable `actual` loads the `index`'th return of external call `callStmt`.  

---
`ArbitraryCall(callStmt:Statement)`

External call `callStmt` has its entire call-data is provided by a caller.

---
`PublicFunctionArg(pubFun:Function, arg:Variable, index:number)`

Variable `arg` is the `index`th argument of public function `pubFun`.

---
#### Array related
---
`VarIsArray(var:Variable, arrId: ArrayVariable)`

Variable `var` is array `arrId`.  
To account for aliasing between different `vars` that point to the same memory address (that is an array) `arrId` is computed and used as a representative var.

---
`ArrayAllocation(arrId:ArrayVariable, elemSize:Value, arrayLength:Variable)`

Array `arrId` is allocated with a type of size `elemSize` and a length equal to the runtime value of variable `arrayLength`.

---
`ArrayStoreAtIndex(stmt:Statement, arrId:ArrayVariable, index:Variable, from:Variable)`  
`ArrayLoadAtIndex(stmt:Statement, arrId:ArrayVariable, index:Variable, to:Variable)`

Statement `stmt` stores `to`/loads `from` array `arrId` at index equal to the runtime value of variable `index`.

---
`ArrayStore(stmt:Statement, arrId:ArrayVariable, from:Variable)`  
`ArrayLoad(stmt:Statement, arrId:ArrayVariable, to:Variable)`

Statement `stmt` stores `to`/loads `from` array `arrId`. These facts do not contain index information, as they are most likely parts of other inferences/patterns, like memory copying loops.

---
`ArrayLengthVar(arrId:ArrayVariable, lenVar:Variable)`

Variable `lenVar` loads the length of array `arrId`.

#### Additional helper relations
The following are relations defined in `clienthelpers.dl` that are not part of the API but included to be reused by many client analyses.

---
`SHA3_1ARG(stmt: Statement, arg: Variable, def: Variable)`  
`SHA3_2ARG(stmt: Statement, arg1: Variable, arg2: Variable, def: Variable)`  
`SHA3_3ARG(stmt: Statement, arg1: Variable, arg2: Variable, arg3: Variable, def: Variable)`

Most common cases of `SHA3` statements with 1, 2, or 3 arguments.  
`SHA3_1ARG` and `SHA3_2ARG` are used to construct storage arrays and mappings.

---
`SHA3_KnownContent(stmt:Statement, hexContent:symbol)`

`SHA3` statement hashes the constant hexadecimal value in `hexContent`.

---
`ExternalCall_NumOfArgs(callStmt:Statement, numOfArgs:number)`

External call `callStmt` has `numOfArgs` arguments through memory.

---
`CallToSignature(callStmt:Statement, sigText:symbol)`

External call `callStmt` calls a high-level function with a signature of `sigText`.

---
`ERC20TransferCall(call:Statement, to:Variable, value:Variable)`  
`ERC20TransferFromCall(call:Statement, from:Variable, to:Variable, value:Variable)`  
`ERC20ApproveCall(call:Statement, spender:Variable, value:Variable)`

Shortcuts to state altering ERC20 functions.

## File layout:

* **memory_modeling.dl**: File to be included by client analyses, includes libs and all memory modeling files.
* **memory_modeling_api.dl**: The API of the memory modeling.
* **clienthelpers.dl**: Other relations that are of use to client analyses.
* **memory_addresses.dl**: Modeling of the free-memory-pointer-based values and the aliasing of memory addresses.
* **core.dl**: The core of the memory modeling. Maps memory reading statements to the memory writting ones. Main output is relation `MemWriteToMemConsStmtResolved`, accounting for sub-word writes.
* **uses_defs_abstractions.dl**: Uses the results of `core.dl` to produce the high-level uses and defs of statements that read from or write to memory.
* **arrays.dl**: Rules about high-level memory arrays.
* **loops.dl**: Modeling of memory copying loops.
* **components.dl**: Common components instantiated various times in the memory modeling. Mainly 3 different flavors of `ReachableByPassing`.
* **helpers.dl**: Syntactic patterns and other shared relations.
* **misc.dl**: Various low-level relations.
* **metrics.dl**: Memory modeling metrics for evaluation.
