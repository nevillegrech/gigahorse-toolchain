# tac.py: Definitions of Three-Address Code operations and related objects.

from typing import List


class Variable:
  """A symbolic variable whose value is supposed to be 
  the result of some TAC operation. Its size is 32 bytes."""

  size = 32

  def __init__(self, ident:str):
    self.identifier = ident

  def __str__(self):
    return self.identifier

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )


class Constant(Variable):
  """A specialised variable whose value is a constant integer."""

  def __init__(self, value:int):
    self.value = value

  def __str__(self):
    return hex(self.value)


class Location:
  """A generic storage location."""

  def __init__(self, space_id:str, size:int, address:Variable):
    """Construct a location from the name of the space,
    and the size of the storage location in bytes."""
    self.space_id = space_id
    self.size = size
    self.address = address

  def __str__(self):
    return "{}[{}]".format(self.space_id, self.address)

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )


class MLoc(Location):
  """A symbolic memory region 32 bytes in length."""
  def __init__(self, address:Variable):
    super().__init__("M", 32, address)


class MLoc8(Location):
  """ A symbolic one-byte cell from memory."""
  def __init__(self, address:Variable):
    super().__init__("M8", 1, address)


class SLoc(Location):
  """A symbolic one word static storage location."""

  def __init__(self, address:Variable):
    super().__init__("S", 32, address)


class TACOp:
  """
  A Three-Address Code operation.
  Each operation consists of a name, and a list of argument variables.
  """

  def __init__(self, name:str, args:List[Variable], address:int):
    self.name = name
    self.args = args
    self.address = address

  def __str__(self):
    return "{}: {} {}".format(hex(self.address), self.name, 
                " ".join([str(arg) for arg in self.args]))

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )


class TACAssignOp(TACOp):
  """
  A TAC operation that additionally takes a variable to which
  this operation's result is implicitly bound.
  """

  def __init__(self, lhs:Variable, name:str,
               args:List[Variable], address:int, print_name=True):
    super().__init__(name, args, address)
    self.lhs = lhs
    self.print_name = print_name

  def __str__(self):
    arglist = ([str(self.name)] if self.print_name else []) \
              + [str(arg) for arg in self.args]
    return "{}: {} = {}".format(hex(self.address), self.lhs, " ".join(arglist))