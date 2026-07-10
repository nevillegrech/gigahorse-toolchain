import subprocess
import pytest
from os.path import join, dirname, abspath

GIGAHORSE_TOOLCHAIN_ROOT = dirname(abspath(__file__))


@pytest.fixture(scope="session", autouse=True)
def gigahorse_prereqs():
    """Runs once, before any test_gigahorse case executes."""
    common_clients = ["-C", join(GIGAHORSE_TOOLCHAIN_ROOT, 'clients/analytics_client.dl')]
    gigahorse_args = ["--disable_scalable_fallback"]
    result = subprocess.run(
            [
                'python3',
                join(GIGAHORSE_TOOLCHAIN_ROOT, 'gigahorse.py'),
                join(GIGAHORSE_TOOLCHAIN_ROOT, 'examples/long_running.hex'),
                '--restart',
                '--jobs', '1',
                '--working_dir', ".tmp_pretest",
                *common_clients,
                *gigahorse_args
            ],
            capture_output=True
        )
    if result.returncode != 0:
        print(result)
        pytest.exit(f"Compilation failed {result.stderr}.", returncode=1)
    yield
    # anything after yield runs once at the very end, e.g. cleanup
