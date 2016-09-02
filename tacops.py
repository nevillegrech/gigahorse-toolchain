# tacops.py: Definitions of Three-Address Code operations and related objects.

class Variable:
  """A symbolic variable whose value is supposed to be the result of some TAC operation."""

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

class Location:
  """A symbolic storage location."""

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
  Each operation consists of a name, and a list of arguments; typically Variables.
  """

  def __init__(self, name, args):
    self.name = name
    self.args = args

  def __str__(self):
    return "{} {}".format(self.name, 
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

  def __init__(self, lhs, name, args, print_name=True):
    super().__init__(name, args)
    self.lhs = lhs
    self.print_name = print_name

  def __str__(self):
    arglist = ([str(self.name)] if self.print_name else []) \
              + [hex(arg) if isinstance(arg, int) else str(arg) for arg in self.args]
    return "{} = {}".format(self.lhs, " ".join(arglist))

