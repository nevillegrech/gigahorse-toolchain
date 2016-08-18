# utils.py: misc. functions used by other Python files in this project

def listdict_add(ldict:dict, key:object, val:object):
  """Adds a given value (val) to the list in a given list-valued dictionary
  (ldict) for the given key"""
  if key in ldict:
    ldict[key].append(val)
  else:
    ldict[key] = [val]
