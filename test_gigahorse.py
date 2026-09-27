#!/usr/bin/env python3

import json
import re
import subprocess
import sys
from collections.abc import Iterator, Mapping, MutableMapping
from os import listdir, makedirs
from os.path import abspath, dirname, isdir, isfile, join
from typing import Any

import pytest

GIGAHORSE_TOOLCHAIN_ROOT = dirname(abspath(__file__))

DEFAULT_TEST_DIR = join(GIGAHORSE_TOOLCHAIN_ROOT, "tests")

TEST_WORKING_DIR = join(GIGAHORSE_TOOLCHAIN_ROOT, ".tests")


class LogicTestCase:
    def __init__(self, name: str, test_root: str, test_path: str, test_config: Mapping[str, Any]):
        super().__init__()

        self.name = name

        client_path = test_config.get("client_path", None)
        self.client_path = abspath(join(dirname(test_root), client_path)) if client_path else None

        self.test_path = test_path

        self.working_dir = abspath(f"{TEST_WORKING_DIR}/{self.name}")
        self.results_file = join(self.working_dir, "results.json")

        self.gigahorse_args = test_config.get("gigahorse_args", [])
        self.contract_specific: dict[str, list[tuple[Any, ...]]] = test_config.get(
            "contract_specific", {}
        )

        self.expected_analytics: list[tuple[str, int, float]] = test_config.get(
            "expected_analytics", []
        )
        self.expected_verbatim: list[tuple[str, str]] = test_config.get("expected_verbatim", [])

    def id(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __run(self) -> subprocess.CompletedProcess:
        client_arg = ["-C", self.client_path] if self.client_path else []

        return subprocess.run(
            [
                sys.executable,
                join(GIGAHORSE_TOOLCHAIN_ROOT, "gigahorse.py"),
                self.test_path,
                "--restart",
                "--jobs",
                "1",
                "--results_file",
                self.results_file,
                "--working_dir",
                self.working_dir,
                *client_arg,
                *self.gigahorse_args,
            ],
            capture_output=True,
        )

    def run(self):
        stderr_path = join(self.working_dir, "stderr")

        def within_margin(actual: int, expected: int, margin: float) -> bool:
            return (1 - margin) * expected <= actual <= (1 + margin) * expected

        def check_finished(contract: str, flags: list[str]):
            failures = [flag for flag in flags if flag in ("ERROR", "TIMEOUT")]
            assert not failures, (
                f"Analysis of {contract} finished with {', '.join(failures)}. See {stderr_path}."
            )

        def check_has_metric(analytics, metric: str, contract: str, flags: list[str]):
            assert metric in analytics, (
                f"No value for {metric} in the results of {contract} (flags: {flags}). "
                f"See {stderr_path}."
            )

        def check_analytics(result_analytics, expected_analytics, contract, flags):
            analytics = {}
            for x, y in result_analytics.items():
                analytics[x] = y

            for metric, expected, margin in expected_analytics:
                check_has_metric(analytics, metric, contract, flags)
                assert within_margin(analytics[metric], expected, margin), (
                    f"Value for {metric} ({analytics[metric]}) not within margin of expected value ({expected})."
                )

        def check_verbatim(result_analytics, expected_verbatim, contract, flags):
            analytics = {}
            for x, y in result_analytics.items():
                analytics[x] = y
            for metric, expected in expected_verbatim:
                check_has_metric(analytics, metric, contract, flags)
                if "*" not in expected:
                    assert analytics[metric] == expected, (
                        f"Value for {metric} ({analytics[metric]}) not the expected value ({expected})."
                    )
                else:
                    regex = re.compile(expected)
                    assert regex.match(analytics[metric]), (
                        f"Value for {metric} ({analytics[metric]}) not the expected value ({expected})."
                    )

        result = self.__run()

        with open(join(self.working_dir, "stdout"), "wb") as f:
            f.write(result.stdout)

        with open(stderr_path, "wb") as f:
            f.write(result.stderr)

        assert result.returncode == 0, f"Gigahorse exited with an error code: {result.returncode}"

        with open(self.results_file) as f:
            res_contents = json.load(f)
            if not self.contract_specific:
                ((contract, _, flags, temp_analytics),) = res_contents
                check_finished(contract, flags)
                check_analytics(temp_analytics, self.expected_analytics, contract, flags)
                check_verbatim(temp_analytics, self.expected_verbatim, contract, flags)
            else:
                results_by_contract = {entry[0]: entry for entry in res_contents}
                for contract, contract_res in self.contract_specific.items():
                    assert contract in results_by_contract, (
                        f"No results for {contract}. See {stderr_path}."
                    )
                    _, _, flags, temp_analytics = results_by_contract[contract]
                    check_finished(contract, flags)
                    check_analytics(
                        temp_analytics, contract_res.get("expected_analytics", {}), contract, flags
                    )
                    check_verbatim(
                        temp_analytics, contract_res.get("expected_verbatim", {}), contract, flags
                    )


def discover_logic_tests(
    current_config: MutableMapping[str, Any], directory: str
) -> Iterator[tuple[Mapping[str, Any], str]]:
    def update_config(config_path: str) -> MutableMapping:
        if isfile(config_path):
            with open(config_path) as f:
                new_config = dict(**current_config)
                new_config.update(json.load(f))

            return new_config
        else:
            return current_config

    current_config = update_config(join(directory, "config.json"))

    for entry in listdir(directory):
        entry_path = join(directory, entry)

        if entry.endswith(".hex") and isfile(entry_path):
            yield update_config(join(directory, f"{entry[:-4]}.json")), entry_path
        elif isdir(entry_path) and isfile(join(directory, f"{entry}.json")):
            yield update_config(join(directory, f"{entry}.json")), entry_path
        elif isdir(entry_path):
            yield from discover_logic_tests(current_config, entry_path)


def collect_tests(test_dirs: list[str]):
    makedirs(TEST_WORKING_DIR, exist_ok=True)

    for test_dir in (abspath(x) for x in test_dirs):
        print(f"Running testcases under {test_dir}")

        for config, test_path in discover_logic_tests({}, test_dir):
            # A test is a .hex file, or a directory of contracts (e.g. for multi-contract tests)
            relative_path = test_path[len(test_dir) + 1 :]
            test_id = relative_path.removesuffix(".hex").replace("/", ".")
            if config:
                testdata.append(
                    pytest.param(LogicTestCase(test_id, test_dir, test_path, config), id=test_id)
                )


testdata = []

collect_tests([DEFAULT_TEST_DIR])


@pytest.mark.usefixtures("gigahorse_prereqs")
@pytest.mark.parametrize("gigahorse_test", testdata)
def test_gigahorse(gigahorse_test):
    gigahorse_test.run()
