# Storage Modeling
Recovers the contract's storage layout and information about statements that deal with storage.
This documentation currently covers the core parts of the storage modeling functionality.
See the [API](storage_modeling_api.dl) and [clienthelpers](clienthelpers.dl) for additional functionality.

## Type Declarations
## `StorageConstruct`
`StorageConstruct` is the main type that defines arbitrarily nested data structures using a nested ADT type.

### Definition
```solidity
.type StorageConstruct = Constant {value: Value}
                        | StaticArray {parConstruct: StorageConstruct, arraySize: number}
                        | Array {parConstruct: StorageConstruct}
                        | Mapping {parConstruct: StorageConstruct}
                        | Offset {parConstruct: StorageConstruct, offset: number}
                        | Variable {construct: StorageConstruct}
                        | TightlyPackedVariable {construct: StorageConstruct, byteLow: number, byteHigh: number}
```

#### Example
The following example can be used to intuitively understand how nested structures are modeled.
Smart contract declarations:
```solidity
contract StorageExample {
  uint256 public supply;  // slot 0x0
  address public owner;   // slot 0x1
  bool public isPaused;   // slot 0x1
  uint256[] public supplies; // slot 0x2
  mapping (address => bool) public admins; // slot 0x3
  struct vals {uint256 field0; uint256 field1;}
  mapping (address => mapping(uint256 => vals)) public complex; // slot 0x4
}
```

Construct inferences:
```solidity
Variable(Constant(0x0)) // uint256 supply
Variable(Constant(0x1)) // address owner , bool isPaused
Variable(Array(Constant(0x2))) // uint256 [] supplies
Variable(Mapping(Constant(0x3))) // mapping admins
// the 2 fields of struct value of nested mapping complex :
Variable(Mapping(Mapping(Constant(0x4))))
Variable(Offset(Mapping(Mapping(Constant(0x4))), 1))
```

## `StorageStmtKind`
The `StorageStmtKind` type is used to describe the kind of load or write a storage statement performs.

### Definition
```solidity
.type StorageStmtKind = VariableAccess {}
                      | ArrayDataStart {}
                      | ArrayLength {}
```

Storage statement kind can be:
* `VariableAccess` which can be used to read or write either:
  * A top-level variable
  * A struct field
  * An array or mapping element
* `ArrayDataStart` which loads or writes to the start location of an array
* `ArrayLength` which is used to load or write the length of an array

## `VarOrConstWrite`
The `VarOrConstWrite` type is introduced to unify writes of variables and constants.

### Definition
```solidity
.type VarOrConstWrite = VariableWrite {var: Variable}
                      | ConstantWrite {const: Value}
```

## Main relations

---
`.decl StorageStmtKindAndConstruct(stmt: Statement, kind: StorageStmtKind, construct: StorageConstruct)`
Maps Storage Stmts to their corresponding construct and their `StorageStmtKind`
__Note__: Storage stmts do not have to be `SSTORE` and `SLOAD` statements, see `StorageLoad` for more info

---
`.decl StorageStmt_HighLevelUses(stmt: Statement, accessVar: Variable, offset: number, i: number, nestedness: number)`
Information about storage stmts on potentially nested data structures.
Can be used to get all information on index variables and field offsets at every step.

---
`.decl StorageLoad(load: Statement, cons: StorageConstruct, loadedVar: Variable)`
Storage load information.
In cases of packed variables a single `SLOAD` can load multiple high-level variables.
In these cases we consider the `load` to not be the `SLOAD` but rather the statement that ends up
extracting the bytes that define the packed variable (cast, etc).

---
`.decl StorageStore(store: Statement, cons: StorageConstruct, write: VarOrConstWrite)`
`SSTORE` statement write information.
A write can be either a Variable or a Constant in cases where the actual written constant doesn't have a corresponding `Variable_Value` fact.  
__Note__: Due to optimized packed variable write patterns, one `SSTORE` can write multiple different constructs

---
`.decl ArrayDeleteOp(sstore: Statement, loop: Block, array: StorageConstruct)`
An `array` is deleted by setting its length to zero in `sstore` and then erasing all its contents in a following `loop`.

---
`.decl DataStructureValueIsStruct(cons: StorageConstruct, structID: symbol, elemNum: number)`
Data structure construct has a value (Mappings) or element (Arrays) that is a struct identified by its `structID`

---
`.decl StructToString(structID: symbol, stringStruct: symbol)`
Map struct identified by `structID` to solidity-like struct definition `stringStruct`.

---



---