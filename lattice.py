class LatticeElement:
	def __init__(self, value=None):
		self.value = value

	def __eq__(self, other):
		return self.value == other.value

	def __str__(self):
		return self.value

TOP = LatticeElement("TOP")
BOTTOM = LatticeElement("BOTTOM")

def is_top(element:LatticeElement):
	return element == TOP

def is_bottom(element:LatticeElement):
	return element == BOTTOM

def meet(a:LatticeElement, b:LatticeElement):
	if is_bottom(a) or is_bottom(b):
		return BOTTOM

	if is_top(a):
		return b
	if is_top(b):
		return a

	return a if a.value == b.value else BOTTOM


