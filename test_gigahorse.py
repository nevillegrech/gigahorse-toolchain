#!/usr/bin/env python3

import subprocess
import pytest
import json
from os.path import abspath, dirname, join, isdir, isfile
from os import listdir, makedirs
from typing import Mapping, MutableMapping, Any, List, Iterator, Tuple

GIGAHORSE_TOOLCHAIN_ROOT = dirname(abspath(__file__))

DEFAULT_TEST_DIR = join(GIGAHORSE_TOOLCHAIN_ROOT, 'tests')

TEST_WORKING_DIR = join(GIGAHORSE_TOOLCHAIN_ROOT, '.tests')


class LogicTestCase():
    def __init__(self, name: str, test_root:str, test_path: str, test_config: Mapping[str, Any]):
        super(LogicTestCase, self).__init__()

        self.name = name

        client_path = test_config.get('client_path', None)
        self.client_path = abspath(join(dirname(test_root), client_path)) if client_path else None

        self.test_path = test_path

        self.working_dir = abspath(f'{TEST_WORKING_DIR}/{self.name}')
        self.results_file = join(self.working_dir, f'results.json')

        self.gigahorse_args = test_config.get('gigahorse_args', [])

        self.expected_analytics: List[Tuple[str, int, float]] = test_config.get("expected_analytics", [])
        self.expected_verbatim: List[Tuple[str, str]] = test_config.get("expected_verbatim", [])

    def id(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __run(self) -> subprocess.CompletedProcess:
        client_arg = ['-C', self.client_path] if self.client_path else []

        return subprocess.run(
            [
                'python3',
                join(GIGAHORSE_TOOLCHAIN_ROOT, 'gigahorse.py'),
                self.test_path,
                '--restart',
                '--jobs', '1',
                '--results_file', self.results_file,
                '--working_dir', self.working_dir,
                *client_arg,
                *self.gigahorse_args
            ],
            capture_output=True
        )

    def __relation_size(self, name: str) -> int:
        hex_name = self.test_path.split('/')[-1].split('.')[-2]

        if isfile(join(self.working_dir, hex_name, 'out', f'{name}.csv')):
            path = join(self.working_dir, hex_name, 'out', f'{name}.csv')
        else:
            path = join(self.working_dir, hex_name, f'{name}.csv')

        with open(path) as f:
            return len(f.readlines())

    def run(self):
        def within_margin(actual: int, expected: int, margin: float) -> bool:
            return (1 - margin) * expected <= actual <= (1 + margin) * expected
        result = self.__run()

        with open(join(self.working_dir, 'stdout'), 'wb') as f:
            f.write(result.stdout)

        with open(join(self.working_dir, 'stderr'), 'wb') as f:
            f.write(result.stderr)

        assert result.returncode == 0, f"Gigahorse exited with an error code: {result.returncode}"

        with open(self.results_file) as f:
            (_, _, _, temp_analytics), = json.load(f)

        analytics = {}
        for x, y in temp_analytics.items():
            analytics[x] = y

        for metric, expected, margin in self.expected_analytics:
            assert within_margin(analytics[metric], expected, margin), f"Value for {metric} ({analytics[metric]}) not within margin of expected value ({expected})."

        for metric, expected in self.expected_verbatim:
            assert analytics[metric] == expected, f"Value for {metric} ({analytics[metric]}) not the expected value ({expected})."


def discover_logic_tests(current_config: MutableMapping[str, Any], directory: str) -> Iterator[Tuple[Mapping[str, Any], str]]:
    def update_config(config_path: str) -> MutableMapping:
        if isfile(config_path):
            with open(config_path) as f:
                new_config = dict(**current_config)
                new_config.update(json.load(f))

            return new_config
        else:
            return current_config

    current_config = update_config(join(directory, 'config.json'))

    for entry in listdir(directory):
        entry_path = join(directory, entry)

        if entry.endswith('.hex') and isfile(entry_path):
            yield update_config(join(directory, f'{entry[:-4]}.json')), entry_path
        elif isdir(entry_path):
            yield from discover_logic_tests(current_config, entry_path)


def collect_tests(test_dirs: List[str]):
    makedirs(TEST_WORKING_DIR, exist_ok=True)

    for test_dir in (abspath(x) for x in test_dirs):
        print(f'Running testcases under {test_dir}')

        for config, hex_path in discover_logic_tests({}, test_dir):
            test_id = hex_path[len(test_dir) + 1:-4].replace('/', '.')
            if config:
                testdata.append(pytest.param(LogicTestCase(test_id, test_dir, hex_path, config), id=test_id))



testdata = []

collect_tests([DEFAULT_TEST_DIR])


@pytest.mark.parametrize("gigahorse_test", testdata)
def test_gigahorse(gigahorse_test):
    gigahorse_test.run()
