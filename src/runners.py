import os
from os.path import join
import subprocess
import pathlib
import hashlib
import resource
import time
import shutil
import json
import re

from typing import Tuple, List, Any, Optional, Dict

from abc import ABC, abstractmethod

from .common import GIGAHORSE_DIR, SOUFFLE_COMPILED_SUFFIX, log
from . import exporter
from . import blockparse

devnull = subprocess.DEVNULL

DEFAULT_MEMORY_LIMIT = 50 * 1_000_000_000
"""Hard capped memory limit for analyses processes (50 GB)"""


souffle_env = os.environ.copy()
functor_path = join(GIGAHORSE_DIR, 'souffle-addon')
for e in ["LD_LIBRARY_PATH", "LIBRARY_PATH"]:
    if e in souffle_env:
        souffle_env[e] = functor_path + os.pathsep + souffle_env[e]
    else:
        souffle_env[e] = functor_path

if not os.path.isfile(join(functor_path, 'libfunctors.so')):
    raise Exception(
        f'Cannot find libfunctors.so in {functor_path}. Make sure you have checked '\
        f'out this repo with --recursive and '\
        f'that you have installed gigahorse correctly (see README.md)'
    )


class TimeoutException(Exception):
    pass

def set_memory_limit(memory_limit: int):
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

def get_souffle_executable_path(cache_dir: str, dl_filename: str) -> str:
    executable_filename = os.path.basename(dl_filename) + SOUFFLE_COMPILED_SUFFIX
    executable_path = join(cache_dir, executable_filename)
    return executable_path

class AnalysisExecutor:
    def __init__(self, timeout: int, interpreted: bool, minimum_client_time: int, debug: bool, souffle_bin: str, cache_dir: str, souffle_macros: str) -> None:
        self.timeout = timeout
        self.interpreted = interpreted
        self.minimum_client_time = minimum_client_time
        self.debug = debug
        self.souffle_bin = souffle_bin
        self.cache_dir = cache_dir
        self.souffle_macros = souffle_macros

    def calc_timeout(self, start_time: float, half: bool = False) -> float:
            timeout_left = self.timeout - time.time() + start_time
            if half:
                timeout_left = timeout_left/2

            return max(timeout_left, self.minimum_client_time)

    def run_souffle_client(self, souffle_client: str, in_dir: str, out_dir: str, start_time: float, half: bool) -> Tuple[List[str], List[str]]:
        errors = []
        timeouts = []
        err_filename = join(out_dir, os.path.basename(souffle_client) + '.err')
        if not self.interpreted:
            err_file: Any = devnull
            analysis_args = [
                get_souffle_executable_path(self.cache_dir, souffle_client),
                f"--facts={in_dir}", f"--output={out_dir}"
            ]
        else:
            err_file = open(err_filename, 'w') if self.debug else devnull
            analysis_args = [
                self.souffle_bin,
                join(os.getcwd(), souffle_client),
                f"--fact-dir={in_dir}", f"--output-dir={out_dir}",
                "-M", self.souffle_macros
            ]

        if run_process(analysis_args, self.calc_timeout(start_time, half), stderr=err_file) < 0:
            timeouts.append(souffle_client)
        if self.debug and err_file != devnull:
            souffle_err = open(err_filename).read()
            # Used to be "Error:" to avoid reporting the file not found errors of souffle
            # However with souffle 2.4 they cause the program to stop so we have to report them as well
            if any(s in souffle_err for s in ["Error", "core dumped", "Segmentation", "corrupted"]):
                errors.append(os.path.basename(souffle_client))
                log(souffle_err)
        return errors, timeouts

    def run_script_client(self, script_client: str, in_dir: str, out_dir: str, start_time: float):
        errors = []
        timeouts = []
        client_split = [o for o in script_client.split(' ') if o]
        client_split[0] = join(os.getcwd(), client_split[0])
        client_name = client_split[0].split('/')[-1]
        err_filename = join(out_dir, client_name+'.err')

        runtime = run_process(
            client_split,
            self.calc_timeout(start_time),
            devnull,
            open(err_filename, 'w'),
            cwd=in_dir
        )
        if len(open(err_filename).read()) > 0:
            errors.append(client_name)
        if runtime < 0:
            timeouts.append(script_client)
        return errors, timeouts


    def run_clients(self, souffle_clients: List[str], other_clients: List[str], in_dir: str, out_dir: str, start_time: float, half: bool = False) -> Tuple[List[str], List[str]]:
        errors = []
        timeouts = []
        for souffle_client in souffle_clients:
            e, t = self.run_souffle_client(souffle_client, in_dir, out_dir, start_time, half)
            errors.extend(e)
            timeouts.extend(t)

        for other_client in other_clients:
            e,t = self.run_script_client(other_client, in_dir, out_dir, start_time)
            errors.extend(e)
            timeouts.extend(t)
        return timeouts, errors

def run_process(process_args, timeout: float, stdout=devnull, stderr=devnull, cwd: str='.', memory_limit=DEFAULT_MEMORY_LIMIT) -> float:
    ''' Runs process described by args, for a specific time period
    as specified by the timeout.

    Returns the time it took to run the process and -1 if the process
    times out
    '''
    if timeout < 0:
        # This can theoretically happen
        return -1

    start_time = time.time()

    try:
        subprocess.run(process_args, timeout=timeout, stdout=stdout, stderr=stderr, cwd=cwd, env=souffle_env, preexec_fn=lambda: set_memory_limit(memory_limit))
    except subprocess.TimeoutExpired:
        return -1

    return time.time() - start_time


def compile_datalog(spec: str, souffle_bin: str, cache_dir: str, reuse_datalog_bin: bool, souffle_macros: str) -> None:
    pathlib.Path(cache_dir).mkdir(exist_ok=True)
    executable_path = get_souffle_executable_path(cache_dir, spec)

    if reuse_datalog_bin and os.path.isfile(executable_path):
        return

    cpp_macros = []
    for macro_def in souffle_macros.split(' '):
        cpp_macros.append('-D')
        cpp_macros.append(macro_def)

    preproc_command = ['cpp', '-P', spec] + cpp_macros
    preproc_process = subprocess.run(preproc_command, universal_newlines=True, capture_output=True)
    assert not(preproc_process.returncode), f"Preprocessing for {spec} failed. Stopping."

    hasher = hashlib.md5()
    hasher.update(preproc_process.stdout.encode('utf-8'))
    md5_hash = hasher.hexdigest()

    cache_path = join(cache_dir, md5_hash)

    if os.path.exists(cache_path):
        log(f"Found cached executable for {spec}")
    else:
        log(f"Compiling {spec} to C++ program and executable")
        compilation_command = [souffle_bin, '-M', souffle_macros, '-o', cache_path, spec, '-L', functor_path]
        process = subprocess.run(compilation_command, universal_newlines=True, env = souffle_env)
        assert not(process.returncode), f"Compilation for {spec} failed. Stopping."

    shutil.copy2(cache_path, executable_path)


def write_context_depth_file(filename: str, max_context_depth: Optional[int] = None) -> None:
    context_depth_file = open(filename, "w")
    if max_context_depth is not None:
        context_depth_file.write(f"{max_context_depth}\n")
    context_depth_file.close()


def imprecise_decomp_out(out_dir: str) -> bool:
    """Used to check if decompilation output is imprecise, currently only checks Analytics_JumpToMany"""
    imprecision_metric = len(open(join(out_dir, 'Analytics_JumpToMany.csv'), 'r').readlines())
    return imprecision_metric > 0


class AbstractFactGenerator(ABC):
    _analysis_executor: AnalysisExecutor
    pattern: re.Pattern

    def __init__(self, args, analysis_executor: AnalysisExecutor):
        pass

    @property
    def analysis_executor(self) -> AnalysisExecutor:
        return self._analysis_executor

    @analysis_executor.setter
    def analysis_executor(self, analysis_executor: AnalysisExecutor):
        self._analysis_executor = analysis_executor

    @abstractmethod
    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str) -> Tuple[float, float, str]:
        pass

    @abstractmethod
    def get_datalog_files(self) -> List[str]:
        pass

    @abstractmethod
    def decomp_out_produced(self, out_dir: str) -> bool:
        pass

    @abstractmethod
    def match_pattern(self, contract_filename: str) -> bool:
        pass


class MixedFactGenerator(AbstractFactGenerator):
    fact_generators: Dict[re.Pattern, AbstractFactGenerator]
    out_dir_to_gen: Dict[str, AbstractFactGenerator]
    contract_filename_to_gen: Dict[str, AbstractFactGenerator]

    def __init__(self, args):
        self.fact_generators = {}
        self.out_dir_to_gen = {}
        self.contract_filename_to_gen = {}

    @property
    def analysis_executor(self) -> AnalysisExecutor:
        return self._analysis_executor

    @analysis_executor.setter
    def analysis_executor(self, analysis_executor: AnalysisExecutor):
        self._analysis_executor = analysis_executor
        for fact_gen in self.fact_generators.values():
            fact_gen.analysis_executor = analysis_executor

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str) -> Tuple[float, float, str]:
        generator = self.contract_filename_to_gen[contract_filename]
        del self.contract_filename_to_gen[contract_filename]
        self.out_dir_to_gen[out_dir] = generator
        return generator.generate_facts(contract_filename, work_dir, out_dir)

    def get_datalog_files(self) -> List[str]:
        datalog_files = []
        for fact_gen in self.fact_generators.values():
            datalog_files += fact_gen.get_datalog_files()
        return datalog_files

    def decomp_out_produced(self, out_dir: str) -> bool:
        result = self.out_dir_to_gen[out_dir].decomp_out_produced(out_dir)
        del self.out_dir_to_gen[out_dir]
        return result

    def match_pattern(self, contract_filename: str) -> bool:
        for gen in self.fact_generators.values():
            if gen.match_pattern(contract_filename):
                self.contract_filename_to_gen[contract_filename] = gen
                return True
        return False

    def add_fact_generator(self, pattern: str, scripts: List[str], is_default: bool, args):
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        if is_default:
            self.fact_generators[re.compile(pattern)] = DecompilerFactGenerator(args, pattern)
        else:
            self.fact_generators[re.compile(pattern)] = CustomFactGenerator(pattern, scripts)


class DecompilerFactGenerator(AbstractFactGenerator):
    decompiler_dl = join(GIGAHORSE_DIR, 'logic/main.dl')
    fallback_scalable_decompiler_dl = join(GIGAHORSE_DIR, 'logic/fallback_scalable.dl')

    def __init__(self, args, pattern: str):
        self.context_depth = args.context_depth
        self.disable_scalable_fallback = args.disable_scalable_fallback
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        self.pattern = re.compile(pattern)

        pre_clients_split = [a.strip() for a in args.pre_client.split(',')]
        self.souffle_pre_clients = [a for a in pre_clients_split if a.endswith('.dl')]
        self.other_pre_clients = [a for a in pre_clients_split if not (a.endswith('.dl') or a == '')]

        if args.disable_precise_fallback:
            log("The use of the --disable_precise_fallback is deprecated. Its functionality is disabled.")

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str) -> Tuple[float, float, str]:
        with open(contract_filename) as file:
            bytecode = file.read().strip()

            if os.path.exists(metad:= f"{contract_filename[:-4]}_metadata.json"):
                metadata = json.load(open(metad))
            else:
                metadata = {}

        disassemble_start = time.time()
        blocks = blockparse.EVMBytecodeParser(bytecode).parse()
        exporter.InstructionTsvExporter(work_dir, blocks, True, bytecode, metadata).export()

        os.symlink(join(work_dir, 'bytecode.hex'), join(out_dir, 'bytecode.hex'))

        if os.path.exists(join(work_dir, 'compiler_info.csv')):
            # Create a symlink with a name starting with 'Verbatim_' to be added to results json
            os.symlink(join(work_dir, 'compiler_info.csv'), join(out_dir, 'Verbatim_compiler_info.csv'))

        timeouts, _ = self.analysis_executor.run_clients(self.souffle_pre_clients, self.other_pre_clients, work_dir, work_dir, disassemble_start)
        if timeouts:
            # pre clients should be very light, should never happen
            raise TimeoutException()

        write_context_depth_file(os.path.join(work_dir, 'MaxContextDepth.csv'), self.context_depth)

        decomp_start = time.time()

        decompiler_config = self.run_decomp(contract_filename, work_dir, out_dir, disassemble_start)

        return decomp_start - disassemble_start, time.time() - decomp_start, decompiler_config

    def get_datalog_files(self) -> List[str]:
        datalog_files = self.souffle_pre_clients + [DecompilerFactGenerator.decompiler_dl]
        if not self.disable_scalable_fallback:
            datalog_files += [DecompilerFactGenerator.fallback_scalable_decompiler_dl]

        return datalog_files

    def run_decomp(self, contract_filename: str, in_dir: str, out_dir: str, start_time: float) -> str:
        config = "default"
        def_timeouts, _ = self.analysis_executor.run_clients([DecompilerFactGenerator.decompiler_dl], [], in_dir, out_dir, start_time, not self.disable_scalable_fallback)

        if def_timeouts or not self.decomp_out_produced(out_dir):
            if self.disable_scalable_fallback:
                raise TimeoutException()
            else:
                # Default using scalable fallback config
                log(f"Using scalable fallback decompilation configuration for {os.path.split(contract_filename)[1]}")
                write_context_depth_file(os.path.join(in_dir, 'MaxContextDepth.csv'), 10)

                sca_timeouts, _ = self.analysis_executor.run_clients([DecompilerFactGenerator.fallback_scalable_decompiler_dl], [], in_dir, out_dir, start_time)
                if not sca_timeouts and self.decomp_out_produced(out_dir):
                    config = "scalable"
                else:
                    raise TimeoutException()

        return config

    def match_pattern(self, contract_filename: str) -> bool:
        return self.pattern.match(contract_filename) is not None

    def decomp_out_produced(self, out_dir: str) -> bool:
        """Hacky. Needed to ensure process was not killed due to exceeding the memory limit."""
        return os.path.exists(join(out_dir, 'Analytics_JumpToMany.csv')) and os.path.exists(join(out_dir, 'TAC_Def.csv'))


class CustomFactGenerator(AbstractFactGenerator):
    def __init__(self, pattern: str, custom_fact_gen_scripts: List[str]):
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        self.pattern = re.compile(pattern)
        self.fact_generator_scripts = custom_fact_gen_scripts

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str) -> Tuple[float, float, str]:
        errors = []
        timeouts = []
        fact_gen_time_start = time.time()
        for script in self.fact_generator_scripts:
            if script.endswith('dl'):
                e,t = self.analysis_executor.run_souffle_client(script, out_dir, out_dir, fact_gen_time_start, False)
                errors.extend(e)
                timeouts.extend(t)
            else:
                arguments = " ".join([script, "-i", os.path.join(os.getcwd(), contract_filename), "-o", out_dir])
                e,t = self.analysis_executor.run_script_client(arguments, work_dir, out_dir, fact_gen_time_start)
                errors.extend(e)
                timeouts.extend(t)
        return time.time() - fact_gen_time_start, 0.0, ""

    def get_datalog_files(self) -> List[str]:
        return [a for a in self.fact_generator_scripts if a.endswith('.dl')]

    def match_pattern(self, contract_filename: str) -> bool:
        return self.pattern.match(contract_filename) is not None

    def decomp_out_produced(self, out_dir: str) -> bool:
        return os.path.exists(join(out_dir, 'TAC_Def.csv'))
