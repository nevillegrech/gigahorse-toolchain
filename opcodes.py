# String -> Constant mapping of disasm opcodes
JUMP = "JUMP"
JUMPI = "JUMPI"
RETURN = "RETURN"
SUICIDE = "SUICIDE"
STOP = "STOP"

PUSH_PREFIX = "PUSH"

JUMPDEST = "JUMPDEST"

def alters_flow(opcode):
  """
  Returns True if opcode alters the EVM control flow.
  """
  return opcode in [
    JUMP, JUMPI, RETURN,
    SUICIDE, STOP
  ]
