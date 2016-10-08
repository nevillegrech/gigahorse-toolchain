"""logger.py: global debug output logging"""

import sys

LOG_LEVEL = 0
"""
Higher values will produce more debug output to stderr.
"""

LOG_FILE = sys.stderr
"""
File-like object where debug output will be logged.
"""

class Verbosity:
  """enum representing the available verbosity levels for logging."""
  HIGH = 3
  MEDIUM = 2
  LOW = 1
  QUIET = 0

def log(message:str, threshold:int = Verbosity.LOW):
  """
  Log the given message to LOG_FILE if LOG_LEVEL exceeds threshold.
  """
  if LOG_LEVEL >= threshold:
    print(message, file=LOG_FILE)
