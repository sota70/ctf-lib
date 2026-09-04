"""Markers the docstring test reads. Nothing here runs at import time."""

from __future__ import annotations

__all__ = ["no_example"]


def no_example(obj):
    """Exempt *obj* from the ``Example:`` requirement.

    ``tests/test_docstrings.py`` demands a doctest in every name exported by
    ``ctflib.__all__``. Decorate the handful where a worked example says less
    than the signature already does::

        @no_example
        def b64_len(n):
            ...

    The mark is a plain attribute, so ``help()`` output is untouched.
    """
    obj.__no_example__ = True
    return obj
