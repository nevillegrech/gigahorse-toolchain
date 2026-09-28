import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
import pathlib
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
import uuid
from abc import ABC, abstractmethod
from enum import Enum
from itertools import groupby
from os.path import join
from pathlib import Path
from typing import Any, NamedTuple

from . import blockparse, exporter
from .common import (
    GIGAHORSE_DIR,
    MAX_CONTEXT_DEPTH_INPUT_FILE,
    SOUFFLE_COMPILED_SUFFIX,
    log,
    log_debug,
)
from .tac_schema import TACRelations, missing_relation_files

devnull = subprocess.DEVNULL

DEFAULT_MEMORY_LIMIT = 50 * 1_000_000_000
"""Hard capped memory limit for analyses processes (50 GB)"""

FALLBACK_SCALABLE_MAX_CONTEXT_DEPTH = 10
LAST_RESORT_MAX_CONTEXT_DEPTH = 10

# Empty at fact generation. Clients that include clientlib/vulnerability_macros.dl add rows.
VULNERABILITY_FILES = ("proto_vulnerability.csv", "vulnerability.csv")

# Client inputs that are not TAC relations
NON_TAC_CLIENT_INPUTS = (
    "StorageContents.csv",
    "SHA3Decompositions.csv",
    MAX_CONTEXT_DEPTH_INPUT_FILE,
)

FACT_GEN_HIGH_PRIORITY = 1
FACT_GEN_LOW_PRIORITY = 2

souffle_env = os.environ.copy()
functor_path = join(GIGAHORSE_DIR, "souffle-addon")
for e in ["LD_LIBRARY_PATH", "LIBRARY_PATH"]:
    if e in souffle_env:
        souffle_env[e] = functor_path + os.pathsep + souffle_env[e]
    else:
        souffle_env[e] = functor_path

if not os.path.isfile(join(functor_path, "libfunctors.so")):
    raise Exception(
        f"Cannot find libfunctors.so in {functor_path}. Make sure you have checked "
        f"out this repo with --recursive and "
        f"that you have installed gigahorse correctly (see README.md)"
    )


class TimeoutException(Exception):
    pass


class DecompilationException(Exception):
    """
    Error during the execution of any fact-producing datalog executable.
    This includes main decompiler, scalable fallback, inliner, and any pre clients.
    Other errors are just output as `client_errors` on the produced json.
    """


def set_memory_limit(memory_limit: int):
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))


# Loaded here, because run_process calls prctl in a forked child
_prctl = ctypes.CDLL(None, use_errno=True).prctl if sys.platform == "linux" else None
PR_SET_PDEATHSIG = 1


def _prepare_child(memory_limit: int, parent_pid: int) -> None:
    set_memory_limit(memory_limit)
    if _prctl is not None:
        _prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
        # The parent can die before the prctl call
        if os.getppid() != parent_pid:
            os._exit(1)


def get_souffle_executable_path(cache_dir: str, dl_filename: str) -> str:
    """
    Path of the most recently compiled executable of `dl_filename`: a link to a binary in the
    cache. The pipeline itself runs the content-addressed binary that `compile_datalog` returns.
    """
    executable_filename = os.path.basename(dl_filename) + SOUFFLE_COMPILED_SUFFIX
    executable_path = join(cache_dir, executable_filename)
    return executable_path


def test_souffle(souffle_bin: str):
    souffle_process = subprocess.run([souffle_bin, "--version"], text=True, capture_output=True)
    assert not (souffle_process.returncode), f"Souffle binary not found at {souffle_bin}. Stopping."
    log_debug("Souffle version info:")
    log_debug(souffle_process.stdout)


class AnalysisExecutor:
    def __init__(
        self,
        timeout: int,
        interpreted: bool,
        minimum_client_time: int,
        debug: bool,
        souffle_bin: str,
        cache_dir: str,
        souffle_macros: str,
    ) -> None:
        self.timeout = timeout
        self.interpreted = interpreted
        self.minimum_client_time = minimum_client_time
        self.debug = debug
        self.souffle_bin = souffle_bin
        self.cache_dir = cache_dir
        self.souffle_macros = souffle_macros
        self.executables: dict[str, str] = {}
        """Absolute path of each compiled datalog program -> path of its binary in the cache."""

    def calc_timeout(self, start_time: float, half: bool = False) -> float:
        timeout_left = self.timeout - time.time() + start_time
        if half:
            timeout_left = timeout_left / 2

        return max(timeout_left, self.minimum_client_time)

    def set_executable(self, souffle_client: str, executable: str) -> None:
        self.executables[os.path.abspath(souffle_client)] = executable

    def get_executable(self, souffle_client: str) -> str:
        return self.executables.get(
            os.path.abspath(souffle_client),
            get_souffle_executable_path(self.cache_dir, souffle_client),
        )

    def run_souffle_client(
        self,
        souffle_client: str,
        in_dir: str,
        out_dir: str,
        start_time: float,
        half: bool,
    ) -> tuple[list[str], list[str]]:
        errors = []
        timeouts = []
        err_filename = join(out_dir, os.path.basename(souffle_client) + ".err")
        if not self.interpreted:
            err_file: Any = open(err_filename, "w")
            analysis_args = [
                self.get_executable(souffle_client),
                f"--facts={in_dir}",
                f"--output={out_dir}",
            ]
        else:
            err_file = open(err_filename, "w") if self.debug else devnull
            analysis_args = [
                self.souffle_bin,
                join(os.getcwd(), souffle_client),
                f"--fact-dir={in_dir}",
                f"--output-dir={out_dir}",
                "-M",
                self.souffle_macros,
            ]

        result = run_process(analysis_args, self.calc_timeout(start_time, half), stderr=err_file)
        if result.timed_out:
            timeouts.append(souffle_client)
        # A crash (for example a segmentation fault) often writes nothing to stderr,
        # thus the exit status is the only sign of it.
        failed = not result.timed_out and result.returncode != 0
        if err_file != devnull:
            err_file.close()
            with open(err_filename, errors="replace") as f:
                souffle_err = f.read()
            # Used to be "Error:" to avoid reporting the file not found errors of souffle
            # However with souffle 2.4 they cause the program to stop so we have to report them as well
            if any(
                s in souffle_err
                for s in [
                    "Error",
                    "error",
                    "core dumped",
                    "Segmentation",
                    "segmentation",
                    "corrupted",
                    "std::",
                ]
            ):
                failed = True
            elif len(souffle_err) > 0:
                log(f"Unrecognized error during {souffle_client} dl execution: {souffle_err}.")
        if failed:
            log(f"{souffle_client} exited with status {result.returncode}")
            errors.append(os.path.basename(souffle_client))
        return errors, timeouts

    def run_script_client(
        self,
        script_client: str,
        in_dir: str,
        out_dir: str,
        start_time: float,
        stderr_is_error: bool = True,
    ):
        """
        Runs a script client with `in_dir` as its working directory. Its stderr goes to
        `<out_dir>/<script name>.err`. A non-zero exit status is an error. Output on stderr
        is also an error, unless `stderr_is_error` is False.
        """
        errors = []
        timeouts = []
        client_split = [o for o in script_client.split(" ") if o]
        client_split[0] = join(os.getcwd(), client_split[0])
        client_name = client_split[0].split("/")[-1]
        err_filename = join(out_dir, client_name + ".err")

        with open(err_filename, "w") as err_file:
            result = run_process(
                client_split,
                self.calc_timeout(start_time),
                devnull,
                err_file,
                cwd=in_dir,
            )
        with open(err_filename, errors="replace") as f:
            client_err = f.read()
        failed = not result.timed_out and result.returncode != 0
        if failed:
            log(f"{client_name} exited with status {result.returncode}")
        if client_err and not stderr_is_error:
            log_debug(f"{client_name} wrote to stderr (see {err_filename})")
        if failed or (client_err and stderr_is_error):
            errors.append(client_name)
        if result.timed_out:
            timeouts.append(script_client)
        return errors, timeouts

    def run_transformer_rounds(
        self,
        souffle_transformer: str,
        rounds: int,
        out_dir: str,
        scratch_dir: str,
        start_time: float,
    ) -> None:
        """
        Runs `souffle_transformer` (for example the inliner) `rounds` times on the IR in `out_dir`.
        A stopped round can leave a mix of old and new relations. Thus each round writes to
        `scratch_dir`, and its files replace the `out_dir` files only when it completes.
        A timeout stops the rounds. Raises DecompilationException if a round fails.
        """
        for _ in range(rounds):
            shutil.rmtree(scratch_dir, ignore_errors=True)
            os.makedirs(scratch_dir)
            timeouts, errors = self.run_clients(
                [souffle_transformer], [], out_dir, scratch_dir, start_time
            )
            completed = not (timeouts or errors)
            for fname in os.listdir(scratch_dir):
                # Always keep the .err file of the round, for debugging
                if completed or fname.endswith(".err"):
                    os.replace(join(scratch_dir, fname), join(out_dir, fname))
            if errors:
                raise DecompilationException(failure_message(errors, out_dir))
            if timeouts:
                break
        shutil.rmtree(scratch_dir, ignore_errors=True)

    def run_clients(
        self,
        souffle_clients: list[str],
        other_clients: list[str],
        in_dir: str,
        out_dir: str,
        start_time: float,
        half: bool = False,
    ) -> tuple[list[str], list[str]]:
        errors = []
        timeouts = []
        for souffle_client in souffle_clients:
            e, t = self.run_souffle_client(souffle_client, in_dir, out_dir, start_time, half)
            errors.extend(e)
            timeouts.extend(t)

        for other_client in other_clients:
            e, t = self.run_script_client(other_client, in_dir, out_dir, start_time)
            errors.extend(e)
            timeouts.extend(t)
        return timeouts, errors


class ProcessResult(NamedTuple):
    runtime: float
    """Seconds the process ran for, or -1 if the timeout stopped it."""
    returncode: int
    """Exit status of the process. A negative value -N means that signal N stopped it."""

    @property
    def timed_out(self) -> bool:
        """
        True if the timeout or a SIGKILL stopped the process. The kernel also sends SIGKILL
        when the system runs out of memory, and gigahorse counts that as a timeout.
        """
        return self.runtime < 0 or self.returncode == -signal.SIGKILL


def run_process(
    process_args,
    timeout: float,
    stdout=devnull,
    stderr=devnull,
    cwd: str = ".",
    memory_limit=DEFAULT_MEMORY_LIMIT,
) -> ProcessResult:
    """Runs process described by args, for a specific time period
    as specified by the timeout.

    Returns the time it took to run the process (-1 if the process
    times out) and its exit status.

    The process runs in a new session. At the timeout, SIGKILL stops the process and
    all the processes that it started, thus none of them can write output later.
    On Linux, the process also stops when its parent dies.
    """
    if timeout < 0:
        # This can theoretically happen
        return ProcessResult(-1, -signal.SIGKILL)

    start_time = time.time()
    parent_pid = os.getpid()

    process = subprocess.Popen(
        process_args,
        stdout=stdout,
        stderr=stderr,
        cwd=cwd,
        env=souffle_env,
        preexec_fn=lambda: _prepare_child(memory_limit, parent_pid),
        start_new_session=True,
    )
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        return ProcessResult(-1, -signal.SIGKILL)
    except BaseException:
        # For example KeyboardInterrupt. The new session does not get the signals of the
        # terminal, thus stop its processes here.
        _kill_process_group(process)
        raise

    return ProcessResult(time.time() - start_time, returncode)


def _kill_process_group(process: subprocess.Popen) -> None:
    """Sends SIGKILL to the process group of `process` (a session leader), then waits for it."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


class DatalogCompilationError(Exception):
    """Preprocessing or compilation of a datalog program failed."""


def _temp_path(path: str) -> str:
    """A unique temporary path next to `path`. Renaming it to `path` is atomic."""
    return f"{path}.{os.getpid()}.{uuid.uuid4().hex}.tmp"


def compile_datalog(
    spec: str,
    souffle_bin: str,
    cache_dir: str,
    reuse_datalog_bin: bool,
    souffle_macros: str,
) -> str:
    """
    Compiles `spec` with `souffle_macros` unless the cache has the binary. Returns its path.
    The name of the binary is the md5 of the preprocessed program. Thus runs that share a cache
    can use different macros, and a run never writes a binary that another run executes.
    Raises DatalogCompilationError if preprocessing or compilation fails.
    """
    pathlib.Path(cache_dir).mkdir(parents=True, exist_ok=True)
    executable_path = get_souffle_executable_path(cache_dir, spec)

    if reuse_datalog_bin and os.path.isfile(executable_path):
        return os.path.realpath(executable_path)

    cpp_macros = []
    for macro_def in souffle_macros.split(" "):
        cpp_macros.append("-D")
        cpp_macros.append(macro_def)

    preproc_command = ["cpp", "-P", spec, *cpp_macros]
    preproc_process = subprocess.run(preproc_command, text=True, capture_output=True)
    if preproc_process.returncode:
        raise DatalogCompilationError(
            f"Preprocessing for {spec} failed. Stopping.\n{preproc_process.stderr}"
        )

    hasher = hashlib.md5()
    hasher.update(preproc_process.stdout.encode("utf-8"))
    md5_hash = hasher.hexdigest()

    log_debug(f"md5 of spec {spec} is {md5_hash}")

    cache_path = join(cache_dir, md5_hash)

    # The lock makes a concurrent run that needs the same binary wait for it, not compile it again
    with open(f"{cache_path}.lock", "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        if os.path.exists(cache_path):
            log(f"Found cached executable for {spec}")
        else:
            comp_start = time.time()
            log(f"Compiling {spec} to C++ program and executable")
            # An interrupted compilation must not leave a partial binary at `cache_path`
            tmp_path = _temp_path(cache_path)
            compilation_command = [
                souffle_bin,
                "-M",
                souffle_macros,
                "-o",
                tmp_path,
                spec,
                "-L",
                functor_path,
            ]
            process = subprocess.run(compilation_command, text=True, env=souffle_env)
            if process.returncode:
                for leftover in (tmp_path, f"{tmp_path}.cpp"):
                    if os.path.exists(leftover):
                        os.remove(leftover)
                raise DatalogCompilationError(f"Compilation for {spec} failed. Stopping.")
            if os.path.exists(f"{tmp_path}.cpp"):
                os.replace(f"{tmp_path}.cpp", f"{cache_path}.cpp")
            os.replace(tmp_path, cache_path)
            log(f"Compilation of {spec} successful after {time.time() - comp_start} seconds.")

    # Point the `<spec>_compiled` link to this binary (for --reuse_datalog_bin)
    tmp_link = _temp_path(executable_path)
    os.symlink(md5_hash, tmp_link)
    os.replace(tmp_link, executable_path)

    return cache_path


DECOMPILATION_STATUS_FILE = "decompilation_status"
"""A file in the working directory of a contract: the state of its decompilation step."""


class DecompilationStatus(str, Enum):
    RUNNING = "RUNNING"
    OK = "OK"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


def write_decompilation_status(work_dir: str, status: DecompilationStatus) -> None:
    path = join(work_dir, DECOMPILATION_STATUS_FILE)
    tmp_path = _temp_path(path)
    with open(tmp_path, "w") as f:
        f.write(f"{status.value}\n")
    os.replace(tmp_path, path)


def read_decompilation_status(work_dir: str) -> DecompilationStatus | None:
    """The recorded status, or None for a working directory of an older gigahorse version."""
    try:
        with open(join(work_dir, DECOMPILATION_STATUS_FILE)) as f:
            return DecompilationStatus(f.read().strip())
    except FileNotFoundError:
        return None


def check_earlier_decompilation(
    work_dir: str, out_dir: str, fact_generator: "AbstractFactGenerator"
) -> None:
    """
    For --rerun_clients. Raises TimeoutException or DecompilationException if the earlier
    decompilation did not complete. A stopped decompiler can leave most of its output files.
    """
    status = read_decompilation_status(work_dir)
    if status is None:
        # No status file: only the output files can tell
        if not fact_generator.decomp_out_produced(out_dir):
            raise TimeoutException("the decompilation of an earlier run did not complete")
    elif status == DecompilationStatus.TIMEOUT:
        raise TimeoutException("the decompilation timed out in an earlier run")
    elif status == DecompilationStatus.ERROR:
        raise DecompilationException("the decompilation failed in an earlier run")
    elif status == DecompilationStatus.RUNNING:
        raise DecompilationException(
            "the decompilation of an earlier run stopped before it completed "
            f"(remove {work_dir} to decompile it again)"
        )


def failure_message(programs: list[str], err_dir: str) -> str:
    return f"{', '.join(programs)} failed, see the .err file in {err_dir}"


def write_context_depth_file(filename: str, max_context_depth: int | None = None) -> None:
    context_depth_file = open(filename, "w")
    if max_context_depth is not None:
        context_depth_file.write(f"{max_context_depth}\n")
    context_depth_file.close()


class FactGenSelectionEnum(str, Enum):
    Decomp = "Decomp"
    MultiContract = "MultiContract"
    Custom = "Custom"


class FactGenUsedEnum(str, Enum):
    DefaultDecomp = "DefaultDecomp"
    ScalableDecomp = "ScalableDecomp"
    LastResortDecomp = "LastResortDecomp"
    MultiContract = "MultiContract"
    Custom = "Custom"


class AbstractFactGenerator(ABC):
    _analysis_executor: AnalysisExecutor
    pattern: re.Pattern
    priority: int

    # Intentional no-op base initializer so concrete generators can call
    # super().__init__(...); each subclass provides its own construction logic.
    def __init__(self, args, analysis_executor: AnalysisExecutor):  # noqa: B027
        pass

    @property
    def analysis_executor(self) -> AnalysisExecutor:
        return self._analysis_executor

    @analysis_executor.setter
    def analysis_executor(self, analysis_executor: AnalysisExecutor):
        self._analysis_executor = analysis_executor

    @abstractmethod
    def generate_facts(
        self, contract_filename: str, work_dir: str, out_dir: str
    ) -> tuple[float, float, FactGenUsedEnum]:
        pass

    @abstractmethod
    def get_datalog_files(self) -> list[str]:
        pass

    @abstractmethod
    def decomp_out_produced(self, out_dir: str) -> bool:
        pass

    @abstractmethod
    def match_pattern(self, contract_filename: str) -> bool:
        pass


class MixedFactGenerator(AbstractFactGenerator):
    fact_generators: dict[re.Pattern, AbstractFactGenerator]
    out_dir_to_gen: dict[str, AbstractFactGenerator]
    contract_filename_to_gen: dict[str, AbstractFactGenerator]

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

    def generate_facts(
        self, contract_filename: str, work_dir: str, out_dir: str
    ) -> tuple[float, float, FactGenUsedEnum]:
        generator = self.contract_filename_to_gen[contract_filename]
        del self.contract_filename_to_gen[contract_filename]  # maybe remove these
        self.out_dir_to_gen[out_dir] = generator
        return generator.generate_facts(contract_filename, work_dir, out_dir)

    def get_datalog_files(self) -> list[str]:
        datalog_files = []
        for fact_gen in self.fact_generators.values():
            datalog_files += fact_gen.get_datalog_files()
        return datalog_files

    def decomp_out_produced(self, out_dir: str) -> bool:
        if out_dir not in self.out_dir_to_gen:
            for fact_gen in self.fact_generators.values():
                if fact_gen.decomp_out_produced(out_dir):
                    return True
            return False

        result = self.out_dir_to_gen[out_dir].decomp_out_produced(out_dir)
        return result

    def match_pattern(self, contract_filename: str) -> bool:
        for gen in self.fact_generators.values():
            if gen.match_pattern(contract_filename):
                self.contract_filename_to_gen[contract_filename] = gen
                return True
        return False

    def add_fact_generator(
        self,
        pattern: str,
        scripts: list[str],
        fact_gen_option: FactGenSelectionEnum,
        args,
    ):
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        compiled_pattern = re.compile(pattern)
        if compiled_pattern in self.fact_generators:
            # The later handler would silently replace the earlier one
            raise ValueError(f"Two TAC generation handlers have the fileRegex {pattern}")
        fact_gen_option = FactGenSelectionEnum(fact_gen_option)
        if fact_gen_option == FactGenSelectionEnum.Custom and not scripts:
            raise ValueError(f"the Custom handler for {pattern} has no customScripts")
        if fact_gen_option == FactGenSelectionEnum.Decomp:
            self.fact_generators[compiled_pattern] = DecompilerFactGenerator(args, pattern)
        elif fact_gen_option == FactGenSelectionEnum.MultiContract:
            self.fact_generators[compiled_pattern] = ContractStitchingGenerator(args, pattern)
        else:
            self.fact_generators[compiled_pattern] = CustomFactGenerator(pattern, scripts)

    def partition_inputs_by_priority(self, files: list[str]) -> list[list[str]]:
        return [
            list(v)
            for _, v in groupby(
                sorted(files, key=lambda x: self.contract_filename_to_gen[x].priority),
                key=lambda x: self.contract_filename_to_gen[x].priority,
            )
        ]


class DecompilerFactGenerator(AbstractFactGenerator):
    decompiler_dl = join(GIGAHORSE_DIR, "logic/main.dl")
    fallback_scalable_decompiler_dl = join(GIGAHORSE_DIR, "logic/fallback_scalable.dl")
    last_resort_decompiler_dl = join(GIGAHORSE_DIR, "logic/last_resort.dl")

    context_depth: int
    disable_scalable_fallback: bool
    souffle_pre_clients: list[str]
    other_pre_clients: list[str]
    skip_sig_resolution: bool

    def __init__(self, args, pattern: str):
        self.context_depth = args.context_depth
        self.disable_scalable_fallback = args.disable_scalable_fallback
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        self.pattern = re.compile(pattern)
        self.priority = FACT_GEN_HIGH_PRIORITY

        pre_clients_split = [a.strip() for a in args.pre_client.split(",")]
        self.souffle_pre_clients = [a for a in pre_clients_split if a.endswith(".dl")]
        self.other_pre_clients = [
            a for a in pre_clients_split if not (a.endswith(".dl") or a == "")
        ]

        self.skip_sig_resolution = args.skip_sig_resolution

        if args.disable_precise_fallback:
            log(
                "The use of the --disable_precise_fallback is deprecated. Its functionality is disabled."
            )

    def generate_facts(
        self, contract_filename: str, work_dir: str, out_dir: str
    ) -> tuple[float, float, FactGenUsedEnum]:
        with open(contract_filename) as file:
            bytecode = file.read().strip()

            if os.path.exists(metad := f"{contract_filename[:-4]}_metadata.json"):
                metadata = json.load(open(metad))
            else:
                metadata = {}

        disassemble_start = time.time()
        blocks = blockparse.EVMBytecodeParser(bytecode).parse()
        exporter.EVMBlockExporter(
            work_dir, blocks, True, bytecode, metadata, self.skip_sig_resolution
        ).export()

        os.symlink(join(work_dir, "bytecode.hex"), join(out_dir, "bytecode.hex"))

        for fname in VULNERABILITY_FILES:
            open(join(out_dir, fname), "w").close()

        if os.path.exists(join(work_dir, "compiler_info.csv")):
            # Create a symlink with a name starting with 'Verbatim_' to be added to results json
            os.symlink(
                join(work_dir, "compiler_info.csv"),
                join(out_dir, "Verbatim_compiler_info.csv"),
            )

        timeouts, errors = self.analysis_executor.run_clients(
            self.souffle_pre_clients,
            self.other_pre_clients,
            work_dir,
            work_dir,
            disassemble_start,
        )
        if timeouts:
            # pre clients should be very light, should never happen
            raise TimeoutException(f"pre-client {', '.join(timeouts)} timed out")
        if errors:
            raise DecompilationException(failure_message(errors, work_dir))

        write_context_depth_file(
            os.path.join(work_dir, MAX_CONTEXT_DEPTH_INPUT_FILE), self.context_depth
        )

        decomp_start = time.time()

        decompiler_config = self.run_decomp(contract_filename, work_dir, out_dir, disassemble_start)

        return (
            decomp_start - disassemble_start,
            time.time() - decomp_start,
            decompiler_config,
        )

    def get_datalog_files(self) -> list[str]:
        datalog_files = [*self.souffle_pre_clients, DecompilerFactGenerator.decompiler_dl]
        if not self.disable_scalable_fallback:
            datalog_files += [
                DecompilerFactGenerator.fallback_scalable_decompiler_dl,
                DecompilerFactGenerator.last_resort_decompiler_dl,
            ]

        return datalog_files

    def run_decomp(
        self, contract_filename: str, in_dir: str, out_dir: str, start_time: float
    ) -> FactGenUsedEnum:
        config = FactGenUsedEnum.DefaultDecomp
        def_timeouts, def_errors = self.analysis_executor.run_clients(
            [DecompilerFactGenerator.decompiler_dl],
            [],
            in_dir,
            out_dir,
            start_time,
            not self.disable_scalable_fallback,
        )

        if def_errors:
            raise DecompilationException(failure_message(def_errors, out_dir))
        elif def_timeouts or not self.decomp_out_produced(out_dir):
            if self.disable_scalable_fallback:
                raise TimeoutException("the decompiler timed out or wrote no output")
            else:
                # Default using scalable fallback config
                log(
                    f"Using the scalable fallback decompilation configuration for {os.path.split(contract_filename)[1]}"
                )
                write_context_depth_file(
                    os.path.join(in_dir, MAX_CONTEXT_DEPTH_INPUT_FILE),
                    FALLBACK_SCALABLE_MAX_CONTEXT_DEPTH,
                )

                sca_timeouts, sca_errors = self.analysis_executor.run_clients(
                    [DecompilerFactGenerator.fallback_scalable_decompiler_dl],
                    [],
                    in_dir,
                    out_dir,
                    start_time,
                    half=True,
                )
                if sca_errors:
                    raise DecompilationException(failure_message(sca_errors, out_dir))
                elif sca_timeouts:
                    log(
                        f"Using the last resort ultra scalable decompilation configuration for {os.path.split(contract_filename)[1]}"
                    )
                    write_context_depth_file(
                        os.path.join(in_dir, MAX_CONTEXT_DEPTH_INPUT_FILE),
                        LAST_RESORT_MAX_CONTEXT_DEPTH,
                    )
                    last_timeouts, last_errors = self.analysis_executor.run_clients(
                        [DecompilerFactGenerator.last_resort_decompiler_dl],
                        [],
                        in_dir,
                        out_dir,
                        start_time,
                    )
                    if last_errors:
                        raise DecompilationException(failure_message(last_errors, out_dir))
                    elif not last_timeouts and self.decomp_out_produced(out_dir):
                        config = FactGenUsedEnum.LastResortDecomp
                    else:
                        raise TimeoutException(
                            "the last resort decompiler configuration timed out or wrote no output"
                        )
                elif not sca_timeouts and self.decomp_out_produced(out_dir):
                    config = FactGenUsedEnum.ScalableDecomp
                else:
                    raise TimeoutException("the scalable decompiler configuration wrote no output")

        return config

    def match_pattern(self, contract_filename: str) -> bool:
        return self.pattern.match(contract_filename) is not None

    def decomp_out_produced(self, out_dir: str) -> bool:
        """Hacky. Needed to ensure process was not killed due to exceeding the memory limit."""
        return os.path.exists(join(out_dir, "Analytics_JumpToMany.csv")) and os.path.exists(
            join(out_dir, "TAC_Def.csv")
        )


class ContractStitchingGenerator(AbstractFactGenerator):
    def __init__(self, args, pattern: str):
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        self.pattern = re.compile(pattern)
        self.priority = FACT_GEN_LOW_PRIORITY

    def generate_facts(
        self, contract_filename: str, work_dir: str, out_dir: str
    ) -> tuple[float, float, FactGenUsedEnum]:
        # TODO: Handle errors
        fact_gen_time_start = time.time()
        with open(contract_filename) as f:
            manifest = json.load(f)

            main = manifest["main"]
            contracts = manifest["contracts"]  # Dict[str, str]
            facts: dict[str, TACRelations] = {}
            for address, contract_id in contracts.items():
                status = read_decompilation_status(str(Path(work_dir).parent / contract_id))
                if status is not None and status != DecompilationStatus.OK:
                    raise DecompilationException(
                        f"contract {contract_id} of the manifest has no complete decompilation "
                        f"({status.value})"
                    )
                path = Path(work_dir).parent / f"{contract_id}/out"
                facts[address] = TACRelations.from_dir(path)

            # copy the bytecode of the main contract, as clients read it
            main_dir = Path(work_dir).parent / contracts[main]
            shutil.copy2(main_dir / "out/bytecode.hex", out_dir)

            for address in facts.keys():
                if address == main:
                    continue
                # TODO: ensure no clashes in the first 8 chars
                facts[address].prefix_identifiers(address[:8] + "_")
                facts[address].set_contract(address)

            merged = TACRelations.merge(*list(facts.values()))
            merged.write_dir(out_dir)

            # Client inputs with no contract column: take them from the main contract
            for fname in NON_TAC_CLIENT_INPUTS:
                # Older working dirs have MaxContextDepth.csv only in the fact dir
                sources = [p for p in (main_dir / "out" / fname, main_dir / fname) if p.is_file()]
                if sources:
                    shutil.copy2(sources[0], out_dir)
                else:
                    open(join(out_dir, fname), "w").close()
            for fname in VULNERABILITY_FILES:
                open(join(out_dir, fname), "w").close()

        return 0, time.time() - fact_gen_time_start, FactGenUsedEnum.MultiContract

    def get_datalog_files(self) -> list[str]:
        return []

    def match_pattern(self, contract_filename: str) -> bool:
        return self.pattern.match(contract_filename) is not None

    def decomp_out_produced(self, out_dir: str) -> bool:
        """Hacky. Needed to ensure process was not killed due to exceeding the memory limit."""
        return os.path.exists(join(out_dir, "TAC_Def.csv"))


class CustomFactGenerator(AbstractFactGenerator):
    def __init__(self, pattern: str, custom_fact_gen_scripts: list[str]):
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        self.pattern = re.compile(pattern)
        self.fact_generator_scripts = custom_fact_gen_scripts
        self.priority = FACT_GEN_HIGH_PRIORITY

    def generate_facts(
        self, contract_filename: str, work_dir: str, out_dir: str
    ) -> tuple[float, float, FactGenUsedEnum]:
        """
        Runs the custom scripts in order. They must write the TAC relations and bytecode.hex
        to `out_dir`. Raises TimeoutException if the timeout or the kernel stops a script, and
        DecompilationException if a script exits with a non-zero status or no TAC_Def.csv exists.
        Output on stderr alone is not an error.
        """
        fact_gen_time_start = time.time()
        for script in self.fact_generator_scripts:
            if script.endswith(".dl"):
                errors, timeouts = self.analysis_executor.run_souffle_client(
                    script, out_dir, out_dir, fact_gen_time_start, False
                )
            else:
                arguments = " ".join(
                    [
                        script,
                        "-i",
                        os.path.join(os.getcwd(), contract_filename),
                        "-o",
                        out_dir,
                    ]
                )
                errors, timeouts = self.analysis_executor.run_script_client(
                    arguments, work_dir, out_dir, fact_gen_time_start, stderr_is_error=False
                )
            if timeouts:
                raise TimeoutException(f"custom fact generation script {script} timed out")
            if errors:
                raise DecompilationException(
                    f"custom fact generation script {failure_message([script], out_dir)}"
                )
        if not self.decomp_out_produced(out_dir):
            raise DecompilationException(
                f"the custom fact generation scripts wrote no TAC_Def.csv to {out_dir}"
            )
        missing = missing_relation_files(out_dir)
        if not os.path.exists(join(out_dir, "bytecode.hex")):
            missing.append("bytecode.hex")
        if missing:
            log(
                f"The custom fact generation scripts wrote no {', '.join(missing)} to {out_dir}. "
                "The inliner and the clients that read these files will fail."
            )
        for fname in (*NON_TAC_CLIENT_INPUTS, *VULNERABILITY_FILES):
            if not os.path.exists(join(out_dir, fname)):
                open(join(out_dir, fname), "w").close()
        # The scripts take the place of the decompiler, as in ContractStitchingGenerator
        return 0.0, time.time() - fact_gen_time_start, FactGenUsedEnum.Custom

    def get_datalog_files(self) -> list[str]:
        return [a for a in self.fact_generator_scripts if a.endswith(".dl")]

    def match_pattern(self, contract_filename: str) -> bool:
        return self.pattern.match(contract_filename) is not None

    def decomp_out_produced(self, out_dir: str) -> bool:
        return os.path.exists(join(out_dir, "TAC_Def.csv"))
