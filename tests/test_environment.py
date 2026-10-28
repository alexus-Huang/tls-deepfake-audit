"""Phase 1 sanity checks: is the environment set up correctly?"""
import sys
from importlib.metadata import version


def test_running_inside_virtualenv():
    assert sys.prefix != sys.base_prefix, "Activate your .venv first!"


def test_python_version_is_supported():
    assert sys.version_info >= (3, 9)


def test_sslyze_importable():
    import sslyze  # noqa: F401
    assert version("sslyze")


def test_pandas_importable():
    import pandas as pd
    df = pd.DataFrame({"domain": ["example.com"]})
    assert len(df) == 1