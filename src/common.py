from os.path import abspath, dirname, join
import os

public_function_signature_filename = join(join(dirname(abspath(__file__)), '..'), 'PublicFunctionSignature.facts')
event_signature_filename = join(join(dirname(abspath(__file__)), '..'), 'EventSignature.facts')
error_signature_filename = join(join(dirname(abspath(__file__)), '..'), 'ErrorSignature.facts')

