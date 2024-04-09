from os.path import abspath, dirname, join, exists
import logging

GIGAHORSE_DIR = join(dirname(abspath(__file__)), '..')
"""The path of the gigahorse-toolchain clone."""

DEFAULT_SOUFFLE_BIN = 'souffle'
"""Location of the Souffle binary."""

SOUFFLE_COMPILED_SUFFIX = '_compiled'

log = lambda msg: logging.log(logging.INFO + 1, msg)


def __get_sig_file(simple_filename: str) -> str:
    preferred_dest = join(join(dirname(abspath(__file__)), '../../common-facts'), simple_filename)
    fallback_dest = join(join(dirname(abspath(__file__)), '..'), simple_filename)
    return preferred_dest if exists(preferred_dest) else fallback_dest

public_function_signature_filename = __get_sig_file('PublicFunctionSignature.facts')
event_signature_filename = __get_sig_file('EventSignature.facts')
error_signature_filename = __get_sig_file('ErrorSignature.facts')

