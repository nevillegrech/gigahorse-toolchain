from os.path import abspath, dirname, join, exists

import os
import logging

GIGAHORSE_DIR = join(dirname(abspath(__file__)), '..')
"""The path of the gigahorse-toolchain clone."""

DEFAULT_SOUFFLE_BIN = 'souffle'
"""Location of the Souffle binary."""

SOUFFLE_COMPILED_SUFFIX = '_compiled'

# The following 4 constants are also defined in `logic/types_defs.dl`
FUNCTION_SELECTOR = "0x0"
FALLBACK_FUNCTION_SIGHASH = "0x00000000"
RECEIVE_FUNCTION_SIGHASH = "0xeeeeeeee"
FUNCTION_SELECTOR_SIGHASH = "0xff5e1ec7"

COMMON_FACTS_DEFAULT_DIR = join(dirname(abspath(__file__)), '../../common-facts')
COMMON_FACTS_DIR = os.environ.get("COMMON_FACTS_DIR", COMMON_FACTS_DEFAULT_DIR)

log = lambda msg: logging.log(logging.INFO + 1, msg)
log_debug = lambda msg: logging.log(logging.DEBUG, msg)

def __get_sig_file(simple_filename: str) -> str:
    preferred_dest = join(join(dirname(abspath(__file__)), '../../common-facts'), simple_filename)
    fallback_dest = join(join(dirname(abspath(__file__)), '..'), simple_filename)
    return preferred_dest if exists(preferred_dest) else fallback_dest

public_function_signature_filename = __get_sig_file('PublicFunctionSignature.facts')
event_signature_filename = __get_sig_file('EventSignature.facts')
error_signature_filename = __get_sig_file('ErrorSignature.facts')

