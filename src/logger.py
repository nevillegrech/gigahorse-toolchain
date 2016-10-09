"""logger.py: global debug output logging"""

import sys
import typing

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

def log(message:str, threshold:int = Verbosity.LOW) -> None:
  """
  Log the given message to LOG_FILE if LOG_LEVEL exceeds threshold.
  """
  if threshold <= LOG_LEVEL:
    print(message, file=LOG_FILE)

def log_high(message:str, *args:typing.Tuple[str]) -> None:
  """
  Log the given message at the HIGH Verbosity level.

  Args:
    message: message to be logged, can be a str.format compatible
    *args: arguments for str.format substitutions in message
  """
  log(message.format(*args), Verbosity.HIGH)

def log_med(message:str, *args:typing.Tuple[str]) -> None:
  """
  Log the given message at the MEDIUM Verbosity level.

  Args:
    message: message to be logged, can be a str.format compatible
    *args: arguments for str.format substitutions in message
  """
  log(message.format(*args), Verbosity.MEDIUM)

def log_low(message:str, *args:typing.Tuple[str]) -> None:
  """
  Log the given message at the LOW Verbosity level.

  Args:
    message: message to be logged, can be a str.format compatible
    *args: arguments for str.format substitutions in message
  """
  log(message.format(*args), Verbosity.LOW)
