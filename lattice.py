# lattice.py: define lattices for use in meet-over-paths calculations.

from functools import reduce

class IntLatticeElement:
	"""An element of the meet-semilattice defined by augmenting
	the (unordered) set of integers with top and bottom elements.

	Integers are incomparable with one another, while top and bottom
	are compare superior and inferior with every other element, respectively."""

	def __init__(self, value:int=None, top:bool=False, bottom:bool=False):
		"""Construct a lattice element with the given value."""
		self.value = value
		self.is_top = top
		self.is_bottom = bottom

		if top:
			self.value = "TOP"
		elif bottom or not self.is_num():
			self.value = "BOTTOM"

	def is_num(self):
		"""True iff the value of this element is an integer."""
		return isinstance(self.value, int)

	def __eq__(self, other):
		return self.value == other.value

	def __str__(self):
		return str(self.value)

	def __repr__(self):
		return "<{0} object {1}, {2}>".format(
			self.__class__.__name__,
			hex(id(self)),
			self.__str__()
		)

	def __add__(self, other):
		if self.is_num() and other.is_num():
			return IntLatticeElement(self.value + other.value)
		if self.is_bottom or other.is_bottom:
			return IntLatticeElement(bottom=True)
		return IntLatticeElement(top=True)

def meet(a:IntLatticeElement, b:IntLatticeElement):
	"""Return the infimum of the given elements."""

	if a.is_bottom or b.is_bottom:
		return IntLatticeElement(bottom=True)

	if a.is_top:
		return b
	if b.is_top:
		return a

	return a if a.value == b.value else IntLatticeElement(bottom=True)

def meet_all(elements):
	"""Return the infimum of the given iterable of elements."""
	return reduce(lambda a, b: meet(a, b), elements, IntLatticeElement(top=True))

# Define a global top and bottom for the lattice.
TOP = IntLatticeElement(top=True)
BOTTOM = IntLatticeElement(bottom=True)

