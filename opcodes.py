# Map disasm opcode strings to Python constants
JUMP = "JUMP"
JUMPI = "JUMPI"
RETURN = "RETURN"
SUICIDE = "SUICIDE"
STOP = "STOP"
JUMPDEST = "JUMPDEST"

# Common prefix of "PUSH"-style operations, used to
# check if a given operation is a PUSH
PUSH_PREFIX = "PUSH"

def alters_flow(opcode:str):
  """
  Returns True if the given opcode (string) alters EVM control flow.
  """
  return opcode in [
    JUMP, JUMPI, RETURN,
    SUICIDE, STOP
  ]
