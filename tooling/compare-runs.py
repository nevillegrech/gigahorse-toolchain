import sys
import json
from pathlib import Path
import argparse


list_of_rels = [
#  'Analytics_NonModeledMSTORE',
#  'Analytics_NonModeledMLOAD',
#  'Analytics_PublicFunctionArg',
#  'Analytics_PublicFunctionArrayArg',
#  'Analytics_ERC20TransferCall',
#  'Analytics_ERC20TransferFromCall',
#  'Analytics_ERC20ApproveCall',
]

list_of_analytics = {
  'decomp_time',
  'client_time',
  'Analytics_NonModeledMSTORE',
  'Analytics_NonModeledMLOAD',
  'Analytics_PublicFunctionArg',
  'Analytics_PublicFunctionArrayArg',
  'Analytics_NonModeledSSTORE',
  'Analytics_NonModeledSLOAD',
  'Analytics_JumpToMany',
# 'Analytics_UselessSLOAD',
#  'Analytics_GlobalVariable',
#  'Analytics_ReachableBlocksInTAC',
#  'Analytics_BlockHasNoTACBlock',
#  'Analytics_LocalBlockEdge',
#  'Analytics_PolymorphicTargetSameCtx',
#  'Analytics_JumpToManyWithoutGlobalImprecision',
#  'Analytics_Blocks',
#  'Analytics_Contexts',
#  'Analytics_JumpToManyWouldHaveBeenCloned',
#  'Analytics_JumpToManyNonPopBlock',
#  'Analytics_MissingJumpTargetAnyCtx',
#  'Analytics_ReachableBlocks',
#  'Analytics_UnreachableBlock'
#  'Analytics_DeadBlocks'
}

list_of_verbatim_rels = {
  'Verbatim_BlocksReachabilityMetric'
}


parser = argparse.ArgumentParser(
                    prog='Compare Runs',
                    description='Compares multiple runs of gigahorse.py using the produced json files')

parser.add_argument('result_files', nargs='*')
parser.add_argument('-v', '--verbose', action='store_true')

args = parser.parse_args()

def process_result_file(filename, output_set=None):
    filemap = dict()

    for rel in list_of_rels:
        filemap[rel] = set()

    for analytic in list_of_analytics:
        filemap[analytic] = 0
    filemap['has_output'] = set()
    filemap['timeout'] = set()

    rels = set(list_of_rels)
    with open(filename) as json_file:
        data = json.load(json_file)
        for contract in data:
            name = contract[0].replace('.hex', '')
            have_output = set(contract[1])
            client_success = "CLIENT TIMEOUT" not in contract[2]

            filemap[name] = dict()
            filemap[name]["rels"] = have_output
            filemap[name]["analytics"] = contract[3]
            if output_set and name not in output_set:
                continue
            if have_output and client_success:
                filemap['has_output'].add(name)
            else:
                filemap['timeout'].add(name)

            for rel in rels & have_output:
                #print(f'contract {name} has vuln {vuln}')
                filemap[rel].add(name)

            for analytic in list_of_analytics:
                if analytic in contract[3]:
                    filemap[analytic] += contract[3][analytic]

            #break
    return filemap


result_files = args.result_files

results_processed = [process_result_file(file) for file in result_files]

has_out = [res['has_output'] for res in results_processed]

has_timeout = [res['timeout'] for res in results_processed]

output_in_any = set.union(*has_out)

output_in_all = set.intersection(*has_out)

timeout_in_all = set.intersection(*has_timeout)

results_processed_common = [process_result_file(file, output_in_all) for file in result_files]

print(f"{len(timeout_in_all) + len(output_in_any)} total contracts")
print(f"{len(output_in_any)} contracts decompiled/analyzed by some config")
print(f"{len(output_in_all)} contracts decompiled/analyzed by all configs \033[1m(common)\033[0m")


if len(result_files) == 2:
    for rel in list_of_rels + ['has_output']:
        not_in_file1 = results_processed[1][rel] - results_processed[0][rel]
        not_in_file2 = results_processed[0][rel] - results_processed[1][rel]
        print(len(results_processed[0][rel]), len(results_processed[1][rel]))
        print(f'\n\nFor {rel} {len(not_in_file1)} not detected by config {Path(result_files[0]).stem}: {not_in_file1}')
        print(f'For {rel} {len(not_in_file2)} not detected by config {Path(result_files[1]).stem}: {not_in_file2}')

for analytic in list_of_analytics:
    print(f'\n\033[1mANALYTIC: {analytic}\033[0m')
    for i in range(0, len(result_files)):
        print(f'{Path(result_files[i]).stem}: {results_processed[i][analytic]}')

    for i in range(0, len(result_files)):
        print(f'{Path(result_files[i]).stem} \033[1m(common)\033[0m: {results_processed_common[i][analytic]}')
