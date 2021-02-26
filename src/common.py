from os.path import abspath, dirname, join

public_function_signature_filename = join(join(dirname(abspath(__file__)), '..'), 'PublicFunctionSignature.facts')
event_signature_filename = join(join(dirname(abspath(__file__)), '..'), 'EventSignature.facts')

## Global behavior files, used to do inter-contract analysis
all_checkedTransferCall_filename = join(join(dirname(abspath(__file__)), '..'), 'All_Component_CheckedTransferCall.csv')
all_checkedTransferFromCall_filename = join(join(dirname(abspath(__file__)), '..'), 'All_Component_CheckedTransferFromCall.csv')
all_readFromTrustedStorageId_filename = join(join(dirname(abspath(__file__)), '..'), 'All_Component_ReadFromTrustedStorageId.csv')
all_unguardedDelegateCallToSig_filename = join(join(dirname(abspath(__file__)), '..'), 'All_Component_UnguardedDelegateCallToSig.csv')
all_unguardedExternalCallToSig_filename = join(join(dirname(abspath(__file__)), '..'), 'All_Component_UnguardedExternalCallToSig.csv')
all_writeToUntrustedStorageId_filename = join(join(dirname(abspath(__file__)), '..'), 'All_Component_WriteToUntrustedStorageId.csv')
