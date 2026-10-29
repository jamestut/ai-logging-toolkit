#!/usr/bin/env python3
"""
Plain HTTP reverse proxy with optional per-request logs.

Inbound side is always HTTP. Upstream may be HTTP or HTTPS. For HTTPS upstreams,
certificate verification is disabled intentionally.
"""

import argparse
import contextlib
import datetime as _dt
import fcntl
import http.client
import http.server
import os
import signal
import socketserver
import ssl
import sys
import threading
import time
import traceback
import urllib.parse
import uuid


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
PID_FILE_NAME = ".sse_proxy.pid"
TOGGLE_ACK_TIMEOUT = 3.0


class ProxyServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind performs a reverse lookup that can stall startup.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def timestamp_name():
    now = _dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return f"{now}-{uuid.uuid4().hex[:8]}.rlog"


def read_pid_metadata(fd):
    # PID file line: PID, logging-enabled flag (0 or 1), and toggle generation.
    # The toggle command waits for the generation to increase after SIGUSR1.
    os.lseek(fd, 0, os.SEEK_SET)
    pid, enabled, generation = os.read(fd, 4096).decode("ascii").split()
    pid = int(pid)
    if pid <= 0:
        raise ValueError("Invalid proxy PID")
    return pid, bool(int(enabled)), int(generation)


def write_pid_metadata(fd, pid, logging_enabled, generation):
    data = f"{pid} {int(logging_enabled)} {generation}\n".encode("ascii")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, data)


def request_logging_toggle(log_dir):
    pid_path = os.path.join(os.path.abspath(log_dir), PID_FILE_NAME)
    try:
        fd = os.open(pid_path, os.O_RDWR)
    except FileNotFoundError:
        print(f"No active proxy found for {log_dir}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Cannot open PID file {pid_path}: {exc}", file=sys.stderr)
        return 1

    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            print(f"No active proxy found for {log_dir}", file=sys.stderr)
            return 1

        try:
            pid, _, generation = read_pid_metadata(fd)
        except (OSError, ValueError):
            print(f"Invalid PID file: {pid_path}", file=sys.stderr)
            return 1

        try:
            os.kill(pid, signal.SIGUSR1)
        except OSError as exc:
            print(f"Could not signal proxy process {pid}: {exc}", file=sys.stderr)
            return 1

        deadline = time.monotonic() + TOGGLE_ACK_TIMEOUT
        while time.monotonic() < deadline:
            try:
                _, enabled, new_generation = read_pid_metadata(fd)
            except (OSError, ValueError):
                pass
            else:
                if new_generation > generation:
                    state = "enabled" if enabled else "disabled"
                    print(f"Per-request logging {state} (proxy PID: {pid})")
                    return 0
            time.sleep(0.05)

        print(
            f"Timed out waiting for proxy process {pid} to acknowledge the toggle",
            file=sys.stderr,
        )
        return 1
    finally:
        os.close(fd)


def install_logging_toggle(log_dir, logging_enabled, parser):
    if not log_dir:
        return None

    os.makedirs(log_dir, exist_ok=True)
    pid_path = os.path.join(log_dir, PID_FILE_NAME)
    pid_fd = os.open(pid_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(pid_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(pid_fd)
        parser.error(f"Another proxy is using the log directory: {log_dir}")
    except OSError:
        os.close(pid_fd)
        raise

    toggle_generation = 0
    write_pid_metadata(
        pid_fd, os.getpid(), logging_enabled.is_set(), toggle_generation
    )

    def handle_logging_toggle(signum, frame):
        nonlocal toggle_generation
        # Signals update new-request state; in-flight requests keep their snapshot.
        if logging_enabled.is_set():
            logging_enabled.clear()
        else:
            logging_enabled.set()
        toggle_generation += 1
        try:
            write_pid_metadata(
                pid_fd,
                os.getpid(),
                logging_enabled.is_set(),
                toggle_generation,
            )
        except OSError as exc:
            print(f"Could not update PID file: {exc}", file=sys.stderr, flush=True)

        state = "enabled" if logging_enabled.is_set() else "disabled"
        directory = f" (directory: {log_dir})" if logging_enabled.is_set() else ""
        print(f"Per-request logging {state}{directory}", flush=True)

    signal.signal(signal.SIGUSR1, handle_logging_toggle)
    return pid_fd


def header_host(parsed):
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        return host
    default_port = 443 if parsed.scheme == "https" else 80
    if port == default_port:
        return host
    return f"{host}:{port}"


def bytes_to_log(data):
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex(" ")


def read_chunked_body(rfile):
    body = bytearray()
    while True:
        line = rfile.readline()
        if not line:
            break
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ValueError(f"invalid chunk size: {line!r}")
        if size == 0:
            # Consume trailer headers until blank line.
            while True:
                trailer = rfile.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        body.extend(rfile.read(size))
        # Consume CRLF after chunk.
        rfile.read(2)
    return bytes(body)


def make_handler(upstream, log_dir, timeout, chunk_size, logging_enabled, verbose=False):
    parsed = urllib.parse.urlparse(upstream)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("--upstream must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("--upstream must include a hostname")

    upstream_host_header = header_host(parsed)
    upstream_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    upstream_base = f"{parsed.scheme}://{upstream_host_header}"

    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if not verbose:
                return
            sys.stderr.write(
                "%s - - [%s] %s\n"
                % (self.client_address[0], self.log_date_time_string(), fmt % args)
            )

        def do_GET(self):
            self.proxy_request()

        def do_POST(self):
            self.proxy_request()

        def do_PUT(self):
            self.proxy_request()

        def do_PATCH(self):
            self.proxy_request()

        def do_DELETE(self):
            self.proxy_request()

        def do_HEAD(self):
            self.proxy_request()

        def do_OPTIONS(self):
            self.proxy_request()

        def read_request_body(self):
            transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
            if "chunked" in transfer_encoding:
                return read_chunked_body(self.rfile)

            content_length = self.headers.get("Content-Length")
            if not content_length:
                return b""
            length = int(content_length)
            return self.rfile.read(length) if length > 0 else b""

        def build_upstream_headers(self, body):
            headers = {}
            for key, value in self.headers.items():
                lower = key.lower()
                if lower in HOP_BY_HOP_HEADERS:
                    continue
                if lower in ("host", "content-length"):
                    continue
                headers[key] = value

            headers["Host"] = upstream_host_header
            if body:
                headers["Content-Length"] = str(len(body))
            elif self.command in ("POST", "PUT", "PATCH"):
                headers["Content-Length"] = "0"
            return headers

        def open_upstream_connection(self):
            if parsed.scheme == "https":
                ctx = ssl._create_unverified_context()
                return http.client.HTTPSConnection(
                    parsed.hostname,
                    upstream_port,
                    timeout=timeout,
                    context=ctx,
                )
            return http.client.HTTPConnection(
                parsed.hostname,
                upstream_port,
                timeout=timeout,
            )

        def write_initial_log(self, log, request_body, upstream_url, upstream_headers):
            log.write("=== LOG INFO ===\n")
            log.write(f"timestamp: {_dt.datetime.now().isoformat()}\n")
            log.write(f"client: {self.client_address[0]}:{self.client_address[1]}\n")
            log.write("\n=== REQUEST HEADERS ===\n")
            log.write(f"{self.command} {self.path} {self.request_version}\n")
            for key, value in self.headers.items():
                log.write(f"{key}: {value}\n")
            log.write("\n=== REQUEST BODY ===\n")
            log.write(bytes_to_log(request_body))
            log.write("\n\n=== UPSTREAM REQUEST HEADERS ===\n")
            log.write(f"{self.command} {upstream_url}\n")
            for key, value in upstream_headers.items():
                log.write(f"{key}: {value}\n")
            log.write("\n")
            log.flush()

        def proxy_request(self):
            log_path = None
            # Snapshot once; later signals affect requests that start afterward.
            request_logging_enabled = logging_enabled.is_set()
            if request_logging_enabled:
                os.makedirs(log_dir, exist_ok=True)
                log_path = os.path.join(log_dir, timestamp_name())
            conn = None

            try:
                request_body = self.read_request_body()
                upstream_headers = self.build_upstream_headers(request_body)
                upstream_path = self.path
                upstream_url = upstream_base + upstream_path

                log_context = (
                    open(log_path, "w", encoding="utf-8", errors="replace")
                    if log_path
                    else contextlib.nullcontext(None)
                )
                with log_context as log:
                    if log is not None:
                        self.write_initial_log(
                            log, request_body, upstream_url, upstream_headers
                        )

                    conn = self.open_upstream_connection()
                    conn.request(
                        self.command,
                        upstream_path,
                        body=request_body if request_body else None,
                        headers=upstream_headers,
                    )
                    resp = conn.getresponse()

                    if log is not None:
                        log.write("=== RESPONSE HEADERS ===\n")
                        log.write(f"HTTP/{resp.version / 10:.1f} {resp.status} {resp.reason}\n")

                    self.send_response(resp.status, resp.reason)
                    response_headers = resp.getheaders()
                    is_sse = False

                    for key, value in response_headers:
                        lower = key.lower()
                        if lower == "content-type" and "text/event-stream" in value.lower():
                            is_sse = True
                        if lower in HOP_BY_HOP_HEADERS:
                            continue
                        if log is not None:
                            log.write(f"{key}: {value}\n")
                        self.send_header(key, value)

                    self.send_header("Connection", "close")
                    self.end_headers()
                    if log is not None:
                        log.write("\n=== RESPONSE BODY ===\n")
                        log.flush()

                    if self.command == "HEAD":
                        return

                    if is_sse:
                        while True:
                            line = resp.readline()
                            if not line:
                                break
                            self.wfile.write(line)
                            self.wfile.flush()
                            if log is not None:
                                log.write(bytes_to_log(line))
                                log.flush()
                    else:
                        while True:
                            chunk = resp.read(chunk_size)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                            if log is not None:
                                log.write(bytes_to_log(chunk))
                                log.flush()

            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected, common for long-lived SSE streams.
                pass
            except Exception:
                err = traceback.format_exc()
                if log_path:
                    try:
                        with open(log_path, "a", encoding="utf-8", errors="replace") as log:
                            log.write("\n=== PROXY ERROR ===\n")
                            log.write(err)
                    except Exception:
                        pass
                if not self.wfile.closed:
                    try:
                        self.send_error(502, "Bad Gateway")
                    except Exception:
                        pass
            finally:
                if conn is not None:
                    conn.close()
                self.close_connection = True

    return ProxyHandler


def main():
    parser = argparse.ArgumentParser(
        description="Plain HTTP reverse proxy with optional per-request logs and SSE support."
    )
    subparsers = parser.add_subparsers(dest="command")
    toggle_parser = subparsers.add_parser(
        "toggle", help="Toggle per-request logging for a running proxy"
    )
    toggle_parser.add_argument(
        "log_dir",
        help="Log directory used by the running proxy",
    )

    parser.add_argument("-b", "--listen-host", default="127.0.0.1", help="Host interface to listen on (default: 127.0.0.1)")
    parser.add_argument("-p", "--listen-port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("-u", "--upstream", help="Upstream URL, http://host or https://host")
    parser.add_argument("-l", "--log-dir", default=None, help="Directory for per-request logs (disabled by default)")
    parser.add_argument("-n", "--no-log", action="store_true", help="Disable per-request logging at startup")
    parser.add_argument("-t", "--timeout", type=float, default=None, help="Upstream socket timeout in seconds (default: None)")
    parser.add_argument("-s", "--chunk-size", type=int, default=8192, help="Read buffer size in bytes (default: 8192)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print HTTP access logs to stderr")
    args = parser.parse_args()

    if args.command == "toggle":
        return request_logging_toggle(args.log_dir)
    if not args.upstream:
        parser.error("--upstream is required")

    log_dir = os.path.abspath(args.log_dir) if args.log_dir else None

    # Event synchronization shares state between the signal handler and request threads.
    # A set event means per-request logging is enabled.
    logging_enabled = threading.Event()
    if log_dir and not args.no_log:
        # A configured log directory starts in the enabled state unless disabled explicitly.
        logging_enabled.set()

    handler = make_handler(
        args.upstream,
        log_dir,
        args.timeout,
        args.chunk_size,
        logging_enabled,
        verbose=args.verbose,
    )
    pid_fd = None
    server = None
    try:
        pid_fd = install_logging_toggle(log_dir, logging_enabled, parser)

        server = ProxyServer(
            (args.listen_host, args.listen_port), handler
        )
        # Keep worker threads from blocking process exit.
        server.daemon_threads = True

        print(f"PID: {os.getpid()}", flush=True)
        print(
            f"Listening on http://{args.listen_host}:{args.listen_port} -> {args.upstream}",
            flush=True,
        )
        if logging_enabled.is_set():
            print(f"Per-request logging enabled (directory: {log_dir})", flush=True)
        else:
            print("Per-request logging disabled", flush=True)

        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...", flush=True)
    finally:
        if server is not None:
            server.server_close()
        if pid_fd is not None:
            # Keep the lock file in place. Unlinking it could let another
            # process lock a new inode while this process holds the old one.
            os.ftruncate(pid_fd, 0)
            # Keep the descriptor open until process exit. Daemon request
            # threads may still be finishing writes after server_close().
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
