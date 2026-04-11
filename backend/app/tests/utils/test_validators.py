import pytest
from fastapi import HTTPException

from app.utils import validators as validators_module
from app.utils.validators import validate_safe_filename


def test_validate_safe_filename_valid():
    assert validate_safe_filename("file.22000") == "file.22000"


def test_validate_safe_filename_rejects_dotdot():
    with pytest.raises(HTTPException) as exc:
        validate_safe_filename("../secret")
    assert exc.value.status_code == 400


def test_validate_safe_filename_rejects_slashes():
    with pytest.raises(HTTPException):
        validate_safe_filename("dir/file")
    with pytest.raises(HTTPException):
        validate_safe_filename("dir\\file")


def test_validate_safe_filename_requires_filename():
    with pytest.raises(HTTPException) as exc:
        validate_safe_filename("")
    assert exc.value.status_code == 400
    assert exc.value.detail["message"] == "Filename required"


def test_validate_safe_filename_rejects_traversal_path(monkeypatch):
    # Force abspath outputs to simulate a traversal mismatch branch.
    values = ["/safe/base", "/outside/base/file.txt"]
    monkeypatch.setattr(
        validators_module.os.path,
        "abspath",
        lambda _p: values.pop(0),
    )

    with pytest.raises(HTTPException) as exc:
        validate_safe_filename("file.txt")
    assert exc.value.status_code == 400
    assert exc.value.detail["message"] == "Path traversal attempt detected"
