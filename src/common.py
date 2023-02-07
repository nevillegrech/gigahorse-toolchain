from os.path import abspath, dirname, join, exists

def __get_sig_file(simple_filename):
    preferred_dest = join(join(dirname(abspath(__file__)), '../../common-facts'), simple_filename)
    fallback_dest = join(join(dirname(abspath(__file__)), '..'), simple_filename)
    return preferred_dest if exists(preferred_dest) else fallback_dest

public_function_signature_filename = __get_sig_file('PublicFunctionSignature.facts')
event_signature_filename = __get_sig_file('EventSignature.facts')
error_signature_filename = __get_sig_file('ErrorSignature.facts')

