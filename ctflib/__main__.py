"""Command line entry points:

    python -m ctflib serve 8000        # log every incoming request (XSS/SSRF callbacks)
    python -m ctflib shell 4444        # reverse shell listener
    python -m ctflib flag 'sknb{*}' file.txt
    python -m ctflib b64 -d            # base64 decode stdin (lenient: padding optional)
    python -m ctflib b64 -e 'admin'    # base64 encode stdin, or the given text
    python -m ctflib url -d / -e       # decodeURIComponent / encodeURIComponent
"""

import sys

from . import (
    App,
    b64decode,
    b64encode,
    decode_uri_component,
    encode_uri_component,
    find_flgs,
    reverse_shell,
)

USAGE = __doc__

_DECODE = ("-d", "--decode")
_ENCODE = ("-e", "--encode")


def _serve(argv):
    port = int(argv[0]) if argv else 8000
    app = App(log=True)
    app.default(lambda req, res: res.text("ok"))
    app.listen(port)


def _shell(argv):
    port = int(argv[0]) if argv else 4444
    reverse_shell(port)


def _flag(argv):
    if not argv:
        print(USAGE, file=sys.stderr)
        return 2
    fmt, files = argv[0], argv[1:]
    if files:
        text = "\n".join(open(name, "r", errors="replace").read() for name in files)
    else:
        text = sys.stdin.read()
    found = find_flgs(text, fmt)
    print("\n".join(found) if found else "", end="\n" if found else "")
    return 0 if found else 1


def _input(argv):
    """The remaining arguments as one string, or stdin -- one trailing newline dropped."""
    text = " ".join(argv) if argv else sys.stdin.read()
    if text.endswith("\n"):
        text = text[:-1]
    return text[:-1] if text.endswith("\r") else text


def _b64(argv):
    if not argv or argv[0] not in _DECODE + _ENCODE:
        print(USAGE, file=sys.stderr)
        return 2
    mode, text = argv[0], _input(argv[1:])
    if mode in _DECODE:
        out = b64decode(text)                 # never raises -- junk and padding are fixed up
        sys.stdout.buffer.write(out + b"\n")
        sys.stdout.buffer.flush()
        return 0 if out else 1
    print(b64encode(text))
    return 0


def _url(argv):
    if not argv or argv[0] not in _DECODE + _ENCODE:
        print(USAGE, file=sys.stderr)
        return 2
    mode, text = argv[0], _input(argv[1:])
    print(decode_uri_component(text) if mode in _DECODE else encode_uri_component(text))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE, file=sys.stderr)
        return 2
    command, rest = argv[0], argv[1:]
    if command == "serve":
        return _serve(rest)
    if command == "shell":
        return _shell(rest)
    if command == "flag":
        return _flag(rest)
    if command == "b64":
        return _b64(rest)
    if command == "url":
        return _url(rest)
    print(f"unknown command: {command}\n\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main() or 0)
