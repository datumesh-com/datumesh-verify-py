"""Error type and the error codes of SPEC.md 10.2."""

from __future__ import annotations

from typing import NoReturn, Optional

#: Every error code SPEC.md 10.2 defines, in the order of its table.
ERROR_CODES: tuple[str, ...] = (
    "E_PARSE_JSON",
    "E_PARSE_DUPLICATE_KEY",
    "E_PARSE_URI",
    "E_SCHEMA",
    "E_CANON_NAME",
    "E_CANON_ARG_NAME",
    "E_CANON_ARG_DUPLICATE",
    "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT",
    "E_CANON_TYPE",
    "E_CANON_NUMBER",
    "E_CANON_DATE",
    "E_CANON_INSTANT",
    "E_CANON_STRING",
    "E_CANON_HEX",
    "E_CANON_LICENCE",
    "E_CANON_SET",
    "E_CANON_LIMIT",
    "E_SLICE",
    "E_PUBLISHER_MISMATCH",
    "E_VALID_MISMATCH",
    "E_TIME_ORDER",
    "E_ARG_UNKNOWN",
    "E_ARG_MISSING",
    "E_KEY_UNAVAILABLE",
    "E_KEY_DOC",
    "E_KEY_UNKNOWN",
    "E_KEY_NOT_VALID",
    "E_SIGNATURE",
    "E_FN_UNAVAILABLE",
    "E_FN_HASH_MISMATCH",
    "E_ARG_TYPE",
    "E_RETURN_TYPE",
    "E_INPUT_UNAVAILABLE",
    "E_INPUT_INVALID",
    "E_INPUT_UNDECLARED",
    "E_VALUE_MISMATCH",
)


class DatumeshError(ValueError):
    """An input broke a rule of the Datumesh specification.

    ``code`` is one of :data:`ERROR_CODES`; ``path`` locates the offending
    member (a JSON path such as ``$.cell.args.base.value``, or ``uri.path`` /
    ``uri.query.<name>`` for cell URIs), or is ``None``.
    """

    code: str
    path: Optional[str]
    detail: str

    def __init__(self, code: str, detail: str = "", path: Optional[str] = None) -> None:
        if code not in ERROR_CODES:
            raise AssertionError(f"unknown error code {code!r}")
        self.code = code
        self.detail = detail
        self.path = path
        where = f" at {path}" if path else ""
        super().__init__(f"{code}{where}: {detail}" if detail else f"{code}{where}")


def fail(code: str, detail: str, path: Optional[str] = None) -> NoReturn:
    raise DatumeshError(code, detail, path)
