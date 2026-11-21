"""OpenSSH ProxyCommand helper for the Windows client.

Usage (from ~/.ssh/sdu-vpn.conf):

    ProxyCommand "…/windows/ssh-proxy.cmd" %h %p

Preferred path is zju-connect's SOCKS5 listener on 127.0.0.1:1080: unlike the
HTTP CONNECT listener on 1081 it does not drop idle tunnels after a few
seconds.  HTTP CONNECT is kept as a fallback for older data-plane builds, and
the final fallback is a direct connection so the same SSH config works in
direct mode.
"""
from __future__ import annotations

import os
import socket
import sys
import threading


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("unexpected EOF")
        data += chunk
    return data


def _socks5(host: str, port: int) -> socket.socket | None:
    try:
        sock = socket.create_connection(("127.0.0.1", 1080), timeout=3)
    except OSError:
        return None
    try:
        sock.sendall(b"\x05\x01\x00")  # SOCKS5, one method: no auth
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS5 auth rejected")
        try:
            host_bytes = host.encode("idna")
        except UnicodeError:
            host_bytes = host.encode("ascii")
        if len(host_bytes) > 255:
            raise OSError("host name too long")
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + port.to_bytes(2, "big")
        )
        sock.sendall(request)
        head = _recv_exact(sock, 4)
        if head[0] != 0x05 or head[1] != 0x00:
            raise OSError(f"SOCKS5 connect failed: {head!r}")
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(sock, 4)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        elif atyp == 0x04:
            _recv_exact(sock, 16)
        else:
            raise OSError("SOCKS5 bad address type")
        _recv_exact(sock, 2)  # bound port
        return sock
    except OSError:
        try:
            sock.close()
        except OSError:
            pass
        return None


def _http_proxy(host: str, port: int) -> socket.socket | None:
    try:
        sock = socket.create_connection(("127.0.0.1", 1081), timeout=3)
    except OSError:
        return None
    try:
        request = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Proxy-Connection: keep-alive\r\n\r\n"
        )
        sock.sendall(request.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(1024)
            if not chunk:
                raise OSError("proxy closed the connection")
            data += chunk
            if len(data) > 8192:
                raise OSError("proxy header too large")
        status = data.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            raise OSError(f"proxy refused: {status!r}")
        return sock
    except OSError:
        try:
            sock.close()
        except OSError:
            pass
        return None


def _pump_in(sock: socket.socket) -> None:
    try:
        while True:
            chunk = os.read(sys.stdin.fileno(), 65536)
            if not chunk:
                break
            sock.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: ssh_proxy.py <host> <port>", file=sys.stderr)
        return 2
    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("invalid port", file=sys.stderr)
        return 2
    if not host or host.startswith("-") or not (1 <= port <= 65535):
        print("invalid host/port", file=sys.stderr)
        return 2

    try:
        sock = _socks5(host, port)
        if sock is None:
            sock = _http_proxy(host, port)
        if sock is None:
            sock = socket.create_connection((host, port), timeout=15)
    except OSError as exc:
        print(f"ssh_proxy: cannot connect to {host}:{port}: {exc}", file=sys.stderr)
        return 1

    threading.Thread(target=_pump_in, args=(sock,), daemon=True).start()
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            os.write(sys.stdout.fileno(), chunk)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    # The stdin pump is blocked in a daemon thread; skip interpreter
    # finalization so it cannot raise "could not acquire lock for stdin".
    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main())
