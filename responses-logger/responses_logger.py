#!/usr/bin/env python3
"""HTTP Responses proxy with per-thread, reconstructible request logs."""

import argparse
import datetime
import fcntl
import http.client
import http.server
import json
import logging
import os
import re
import signal
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path


HOP_HEADERS = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"})
LOG_NAME = re.compile(r"^(\d{5,})(?:-(\d{2,}))?\.rlog$")
PID_FILE = ".responses_logger.pid"


class ClientError(Exception):
    pass


class StateError(Exception):
    pass


def uuid7(value):
    try:
        parsed = uuid.UUID(value)
        if parsed.version != 7 or parsed.variant != uuid.RFC_4122:
            raise ValueError
        millis = parsed.int >> 80
        moment = datetime.datetime.fromtimestamp(millis / 1000, datetime.timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        raise ClientError("session-id and thread-id must be valid UUIDv7 values") from None
    return parsed, f"{moment:%Y%m%d-%H%M%S}-{millis % 1000:03d}-{parsed.hex[-8:]}"


def connection_headers(headers):
    names = set(HOP_HEADERS)
    for value in headers.get_all("Connection", []):
        names.update(item.strip().lower() for item in value.split(","))
    return names


def body_from_log(path):
    try:
        text = path.read_text(encoding="utf-8")
        request, rest = text.split("\n=== REQUEST BODY ===\n", 1)
        body, rest = rest.split("\n\n=== LOG METADATA ===\n", 1)
        metadata, _ = rest.split("\n\n=== RESPONSE HEADERS ===\n", 1)
        headers = {}
        for line in request.split("=== REQUEST HEADERS ===\n", 1)[1].splitlines()[1:]:
            key, value = line.split(":", 1)
            headers.setdefault(key.lower(), value.strip())
        return headers, json.loads(body), json.loads(metadata)
    except (OSError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
        raise StateError(f"Cannot read log {path}: {exc}") from exc


def log_files(directory):
    if not directory.exists():
        return []
    found = []
    for path in directory.iterdir():
        match = LOG_NAME.fullmatch(path.name)
        if match and path.is_file():
            found.append((int(match[1]), int(match[2] or 0), path))
    return sorted(found)


def log_identity(path):
    try:
        headers = {}
        with path.open(encoding="utf-8") as source:
            for line in source:
                if line.rstrip("\r\n") == "=== REQUEST BODY ===":
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.lower() in ("session-id", "thread-id"):
                        headers.setdefault(key.lower(), value.strip())
        return uuid.UUID(headers["session-id"]), uuid.UUID(headers["thread-id"])
    except (OSError, KeyError, ValueError) as exc:
        raise StateError(f"Cannot read log identity {path}: {exc}") from exc


def check_identity(session_dir, thread_dir, session_id, thread_id):
    # The path contains only part of each UUID, so check the complete stored IDs.
    if session_dir.exists():
        for child in session_dir.iterdir():
            if child.is_dir():
                files = log_files(child)
                if files:
                    stored_session, _ = log_identity(files[0][2])
                    if stored_session != session_id:
                        raise StateError(f"Session directory collision: {session_dir}")
    files = log_files(thread_dir)
    if files:
        if log_identity(files[0][2]) != (session_id, thread_id):
            raise StateError(f"Thread directory collision: {thread_dir}")
    return files


@dataclass
class ThreadState:
    sequence: int = 0
    input: object = None
    full_sequence: int = 0
    last_used: float = 0.0


def is_delta_body(body, metadata):
    mode = metadata.get("body_mode")
    if mode is not None:
        if mode not in ("full", "delta"):
            raise StateError("Invalid request body mode in log metadata")
        return mode == "delta"
    return isinstance(body, dict) and "continuation" in body and "input_delta" in body


def restore(files):
    if not files:
        return ThreadState()
    # A numbered request can have retries. Its latest recorded attempt has the
    # same representation, so apply only one attempt from each numbered group.
    groups = {}
    for sequence, retry, path in files:
        groups[sequence] = (retry, path)
    last_sequence = max(groups)
    _, last_path = groups[last_sequence]
    _, last_body, last_meta = body_from_log(last_path)
    if not isinstance(last_meta, dict):
        raise StateError(f"Invalid log metadata in {last_path}")
    last_is_delta = is_delta_body(last_body, last_meta)
    base = last_body.get("continuation") if last_is_delta and isinstance(last_body, dict) else None
    if last_is_delta and base is None:
        raise StateError(f"Invalid continuation reference in {last_path}")
    if base is None:
        base = last_sequence
    if type(base) is not int or base < 1 or base > last_sequence or base not in groups:
        raise StateError(f"Invalid continuation reference in {last_path}")
    sequences = sorted(n for n in groups if base <= n <= last_sequence)
    if len(sequences) != last_sequence - base + 1:
        raise StateError(f"Missing request in continuation chain ending at {last_path}")
    current_input = None
    full_sequence = 0
    for sequence in sequences:
        _, path = groups[sequence]
        _, body, meta = body_from_log(path)
        if not isinstance(body, dict) or not isinstance(meta, dict):
            raise StateError(f"Invalid request body or metadata in {path}")
        if is_delta_body(body, meta):
            if type(body.get("continuation")) is not int or body["continuation"] != full_sequence or not isinstance(current_input, list) or not isinstance(body.get("input_delta"), list):
                raise StateError(f"Invalid continuation chain in {path}")
            current_input = current_input + body["input_delta"]
        else:
            current_input = body.get("input")
            full_sequence = sequence
    if full_sequence != base:
        raise StateError(f"Invalid full request reference in {last_path}")
    return ThreadState(sequence=last_sequence, input=current_input, full_sequence=full_sequence)


def stored_request(body, state):
    input_items = body.get("input")
    if isinstance(input_items, list) and isinstance(state.input, list) and input_items[:len(state.input)] == state.input and state.full_sequence:
        # Reference the last full request while storing only the suffix added since the previous request.
        return {"continuation": state.full_sequence, "input_delta": input_items[len(state.input):]}
    return body


def turn_id(body):
    metadata = body.get("client_metadata")
    value = metadata.get("turn_id") if isinstance(metadata, dict) else None
    return value if isinstance(value, str) and value else None


def read_chunked(stream):
    result = bytearray()
    while True:
        line = stream.readline(65537)
        if not line or len(line) > 65536:
            raise ClientError("Invalid chunked request body")
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            raise ClientError("Invalid chunk size") from None
        if size < 0:
            raise ClientError("Invalid chunk size")
        if size == 0:
            while True:
                trailer = stream.readline(65537)
                if not trailer or len(trailer) > 65536:
                    raise ClientError("Invalid chunk trailer")
                if trailer in (b"\r\n", b"\n"):
                    return bytes(result)
        chunk = stream.read(size)
        if len(chunk) != size or stream.read(2) != b"\r\n":
            raise ClientError("Incomplete chunked request body")
        result.extend(chunk)


def read_request(handler):
    encodings = handler.headers.get_all("Transfer-Encoding", [])
    lengths = handler.headers.get_all("Content-Length", [])
    if encodings:
        if lengths or ",".join(encodings).strip().lower() != "chunked":
            raise ClientError("Unsupported request transfer encoding")
        return read_chunked(handler.rfile)
    if len(lengths) != 1:
        raise ClientError("A single Content-Length is required")
    try:
        length = int(lengths[0])
        if length < 0:
            raise ValueError
    except ValueError:
        raise ClientError("Invalid Content-Length") from None
    data = handler.rfile.read(length)
    if len(data) != length:
        raise ClientError("Incomplete request body")
    return data


class SSEParser:
    def __init__(self):
        self.buffer = bytearray()
        self.lines = []
        self.completed = None

    def feed(self, data):
        self.buffer.extend(data)
        while True:
            pos = self.buffer.find(b"\n")
            if pos < 0:
                return
            line = bytes(self.buffer[:pos]).rstrip(b"\r")
            del self.buffer[:pos + 1]
            if line:
                self.lines.append(line)
                continue
            event = None
            parts = []
            for line in self.lines:
                field, sep, value = line.partition(b":")
                if sep and value.startswith(b" "):
                    value = value[1:]
                if field == b"event":
                    event = value
                elif field == b"data":
                    parts.append(value)
            self.lines.clear()
            if event == b"response.completed" and parts:
                try:
                    value = json.loads(b"\n".join(parts))
                    if isinstance(value, dict):
                        self.completed = value
                except (ValueError, UnicodeDecodeError):
                    pass


class ProxyServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def server_bind(self):
        # Bypass HTTPServer.server_bind's reverse DNS lookup for the server name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class App:
    def __init__(self, args):
        self.args = args
        self.directory = Path(args.log_dir).resolve()
        self.upstream = urllib.parse.urlsplit(args.upstream)
        if self.upstream.scheme not in ("http", "https") or not self.upstream.hostname or self.upstream.fragment or self.upstream.username is not None:
            raise ValueError("Upstream must be an HTTP(S) URL without credentials or fragment")
        self.upstream.port  # Accessing the property parses and validates the port.
        self.enabled = threading.Event()
        if not args.no_log:
            self.enabled.set()
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.locks = [threading.Lock() for _ in range(256)]
        self.identity_lock = threading.Lock()
        self.active_sessions = {}
        self.active_threads = {}
        self.logger = logging.getLogger("responses-logger")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.directory / "program.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(handler)

    def prune_cache(self):
        now = time.monotonic()
        with self.cache_lock:
            expired = [k for k, value in self.cache.items() if now - value.last_used >= self.args.cache_minutes * 60]
            for k in expired:
                del self.cache[k]

    def reserve_identity(self, session_dir, thread_dir, session_id, thread_id):
        # Reserve paths while requests are in flight, before either can create a log.
        with self.identity_lock:
            active_session = self.active_sessions.get(session_dir)
            active_thread = self.active_threads.get(thread_dir)
            if active_session and active_session[0] != session_id:
                raise StateError(f"Session directory collision: {session_dir}")
            if active_thread and active_thread[0] != (session_id, thread_id):
                raise StateError(f"Thread directory collision: {thread_dir}")
            files = check_identity(session_dir, thread_dir, session_id, thread_id)
            self.active_sessions[session_dir] = (session_id, (active_session[1] if active_session else 0) + 1)
            self.active_threads[thread_dir] = ((session_id, thread_id), (active_thread[1] if active_thread else 0) + 1)
            return files

    def release_identity(self, session_dir, thread_dir):
        with self.identity_lock:
            for mapping, path in ((self.active_sessions, session_dir), (self.active_threads, thread_dir)):
                identity, count = mapping[path]
                if count == 1:
                    del mapping[path]
                else:
                    mapping[path] = (identity, count - 1)

    def state(self, key, files):
        now = time.monotonic()
        with self.cache_lock:
            cached = self.cache.get(key)
            if cached is not None:
                cached.last_used = now
                return cached
        state = restore(files)
        state.last_used = now
        with self.cache_lock:
            self.cache[key] = state
        return state

    def save(self, state, body, representation, current_turn, headers, response_status, response_headers, response_body, thread_dir, request_line):
        sequence = state.sequence + 1
        name = f"{sequence:05d}.rlog"
        thread_dir.mkdir(parents=True, exist_ok=True)
        destination = thread_dir / name
        request_headers = "".join(f"{key}: {value}\n" for key, value in headers.raw_items())
        response_header_text = "".join(f"{key}: {value}\n" for key, value in response_headers)
        is_delta = representation is not body
        content = (f"=== REQUEST HEADERS ===\n{request_line}\n{request_headers}\n=== REQUEST BODY ===\n"
                   + json.dumps(representation, ensure_ascii=False, separators=(",", ":"))
                   + "\n\n=== LOG METADATA ===\n" + json.dumps({"turn_id": current_turn, "body_mode": "delta" if is_delta else "full"}, ensure_ascii=False, separators=(",", ":"))
                   + f"\n\n=== RESPONSE HEADERS ===\n{response_status}\n{response_header_text}\n=== RESPONSE BODY ===\n"
                   + json.dumps(response_body, ensure_ascii=False, separators=(",", ":")) + "\n")
        temporary = None
        try:
            # Write in the destination directory so replacement publishes a complete log atomically.
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=thread_dir, prefix=".pending-", delete=False) as output:
                temporary = output.name
                os.fchmod(output.fileno(), 0o600)
                output.write(content)
            if destination.exists():
                raise StateError(f"Log already exists: {destination}")
            os.replace(temporary, destination)
            temporary = None
        finally:
            if temporary:
                os.unlink(temporary)
        state.sequence = sequence
        state.input = body.get("input")
        if not is_delta:
            state.full_sequence = sequence
        state.last_used = time.monotonic()


def handler_for(app):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if app.args.verbose:
                super().log_message(fmt, *args)

        def log_error(self, fmt, *args):
            app.logger.warning("HTTP request handling error")
            if app.args.verbose:
                super().log_error(fmt, *args)

        def reject(self, status, message):
            app.logger.warning("Request rejected: %s %s: %s", self.command, self.path.split("?", 1)[0], message)
            self.close_connection = True
            self.send_error(status, message)

        def do_GET(self):
            self.reject(405, "Only POST /v1/responses is supported")

        do_HEAD = do_GET
        do_PUT = do_GET
        do_PATCH = do_GET
        do_DELETE = do_GET
        do_OPTIONS = do_GET

        def do_POST(self):
            logging_enabled = app.enabled.is_set()
            app.prune_cache()
            parsed_path = urllib.parse.urlsplit(self.path)
            if parsed_path.path != "/v1/responses" or parsed_path.scheme or parsed_path.netloc:
                self.reject(404, "Only POST /v1/responses is supported")
                return
            if self.headers.get("Upgrade") or "upgrade" in self.headers.get("Connection", "").lower():
                self.reject(400, "WebSocket upgrades are unsupported")
                return
            if self.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
                self.reject(400, "Compressed request bodies are unsupported")
                return
            try:
                if len(self.headers.get_all("session-id", [])) != 1 or len(self.headers.get_all("thread-id", [])) != 1:
                    raise ClientError("Exactly one session-id and thread-id are required")
                session_id, session_name = uuid7(self.headers["session-id"])
                thread_id, thread_name = uuid7(self.headers["thread-id"])
                raw_body = read_request(self)
                body = json.loads(raw_body)
                if not isinstance(body, dict):
                    raise ClientError("Request body must be a JSON object")
            except (ClientError, ValueError, UnicodeDecodeError) as exc:
                self.reject(400, str(exc))
                return
            key = (session_id, thread_id)
            session_dir = app.directory / session_name
            thread_dir = session_dir / ("root" if session_id == thread_id else thread_name)
            # Keep requests for the same thread ordered through forwarding and logging.
            with app.locks[hash(key) % len(app.locks)]:
                reserved = False
                try:
                    files = app.reserve_identity(session_dir, thread_dir, session_id, thread_id)
                    reserved = True
                    state = app.state(key, files) if logging_enabled else None
                    self.forward(parsed_path, raw_body, body, state, thread_dir)
                except (StateError, OSError) as exc:
                    app.logger.error("Thread %s: %s", thread_id, exc)
                    if not getattr(self, "response_started", False):
                        self.send_error(500, "Log state unavailable")
                    self.close_connection = True
                finally:
                    if reserved:
                        app.release_identity(session_dir, thread_dir)

        def forward(self, incoming, raw_body, body, state, thread_dir):
            self.response_started = False
            current_turn = turn_id(body)
            representation = stored_request(body, state) if state is not None else None
            upstream = app.upstream
            path = upstream.path or "/"
            query = "&".join(part for part in (upstream.query, incoming.query) if part)
            if query:
                path += "?" + query
            port = upstream.port or (443 if upstream.scheme == "https" else 80)
            cls = http.client.HTTPSConnection if upstream.scheme == "https" else http.client.HTTPConnection
            options = {"timeout": app.args.timeout}
            if upstream.scheme == "https":
                options["context"] = ssl.create_default_context()
            conn = cls(upstream.hostname, port, **options)
            try:
                conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
                blocked = connection_headers(self.headers) | {"host", "content-length", "accept-encoding"}
                host = upstream.netloc
                conn.putheader("Host", host)
                for key, value in self.headers.raw_items():
                    if key.lower() not in blocked:
                        conn.putheader(key, value)
                conn.putheader("Content-Length", str(len(raw_body)))
                conn.putheader("Accept-Encoding", "identity")
                conn.endheaders(raw_body)
                response = conn.getresponse()
                response_headers = response.getheaders()
                excluded = set(HOP_HEADERS)
                for key, value in response_headers:
                    if key.lower() == "connection":
                        excluded.update(part.strip().lower() for part in value.split(","))
                    if key.lower() == "transfer-encoding":
                        # http.client removes chunk framing while reading the response.
                        excluded.add("content-length")
                self.send_response_only(response.status, response.reason)
                for key, value in response_headers:
                    if key.lower() not in excluded:
                        self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.response_started = True
                self.close_connection = True
                self.copy_response(response, response_headers, state, body, representation, current_turn, thread_dir)
            except (OSError, http.client.HTTPException) as exc:
                app.logger.warning("Upstream or client connection failed: %s", exc)
                if not self.response_started:
                    self.send_error(502, "Upstream connection failed")
                self.close_connection = True
            finally:
                conn.close()

        def copy_response(self, response, response_headers, state, body, representation, current_turn, thread_dir):
            prefix = bytearray()
            kind = None
            parser = SSEParser()
            json_body = bytearray()
            while True:
                chunk = response.read1(app.args.chunk_size)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                if kind is None:
                    # Detect the body format from its first non-whitespace byte, even across chunks.
                    prefix.extend(chunk)
                    stripped = bytes(prefix).lstrip(b" \t\r\n")
                    if stripped:
                        kind = "json" if stripped[:1] in (b"{", b"[") else "sse"
                    elif len(prefix) >= 4096:
                        kind = "json"
                    if kind is None:
                        continue
                    chunk = bytes(prefix)
                    prefix.clear()
                if kind == "sse":
                    parser.feed(chunk)
                elif state is not None:
                    json_body.extend(chunk)
            if kind == "sse":
                result = parser.completed
                if result is None:
                    app.logger.warning("Thread %s: response.completed missing or invalid", self.headers.get("thread-id"))
                    return
            else:
                if state is None:
                    return
                json_body.extend(prefix)
                try:
                    result = json.loads(json_body)
                except (ValueError, UnicodeDecodeError):
                    app.logger.warning("Thread %s: upstream response is not valid JSON", self.headers.get("thread-id"))
                    return
            if state is None:
                return
            status = f"HTTP/{response.version // 10}.{response.version % 10} {response.status} {response.reason}"
            try:
                app.save(state, body, representation, current_turn, self.headers, status, response_headers, result, thread_dir, self.requestline)
            except OSError as exc:
                raise StateError(f"Cannot write request log in {thread_dir}: {exc}") from exc

    return Handler


def read_pid(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    pid, enabled, generation = os.read(fd, 4096).decode("ascii").split()
    return int(pid), int(enabled), int(generation)


def write_pid(fd, enabled, generation):
    data = f"{os.getpid()} {int(enabled)} {generation}\n".encode("ascii")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, data)


def toggle(directory):
    try:
        fd = os.open(Path(directory).resolve() / PID_FILE, os.O_RDWR)
        try:
            # A failed nonblocking lock means a proxy still holds the file lock.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise ValueError("No active proxy for this log directory")
            pid, _, generation = read_pid(fd)
            if pid <= 0:
                raise ValueError("Invalid proxy PID")
            os.kill(pid, signal.SIGUSR1)
            deadline = time.monotonic() + 3
            # The signal handler increments the generation after applying the toggle.
            while time.monotonic() < deadline:
                try:
                    _, enabled, current = read_pid(fd)
                    if current > generation:
                        print(f"Request logging {'enabled' if enabled else 'disabled'} (PID {pid})")
                        return 0
                except (ValueError, OSError):
                    pass
                time.sleep(0.05)
            raise ValueError("Timed out waiting for toggle acknowledgement")
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        print(f"Toggle failed: {exc}", file=sys.stderr)
        return 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "toggle":
        parser = argparse.ArgumentParser(description="Toggle request logging for a running proxy")
        parser.add_argument("command")
        parser.add_argument("log_dir")
        args = parser.parse_args()
        return toggle(args.log_dir)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-u", "--upstream", required=True, help="Complete upstream Responses endpoint URL")
    parser.add_argument("-l", "--log-dir", required=True, help="Directory for request and program logs")
    parser.add_argument("-b", "--listen-host", default="127.0.0.1")
    parser.add_argument("-p", "--listen-port", type=int, default=8000)
    parser.add_argument("-n", "--no-log", action="store_true", help="Start with request logging disabled")
    parser.add_argument("-t", "--timeout", type=float, default=None, help="Upstream socket timeout in seconds")
    parser.add_argument("-s", "--chunk-size", type=int, default=8192)
    parser.add_argument("--cache-minutes", type=float, default=30, help="Cache idle timeout in minutes")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.cache_minutes <= 0 or args.chunk_size <= 0 or (args.timeout is not None and args.timeout <= 0):
        parser.error("cache-minutes, chunk-size, and timeout must be positive")
    directory = Path(args.log_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / PID_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        parser.error("Another proxy is using the log directory")
    try:
        app = App(args)
        generation = 0
        write_pid(fd, app.enabled.is_set(), generation)

        def on_toggle(signum, frame):
            nonlocal generation
            if app.enabled.is_set():
                app.enabled.clear()
            else:
                app.enabled.set()
            generation += 1
            try:
                write_pid(fd, app.enabled.is_set(), generation)
            except OSError as exc:
                app.logger.error("Cannot update toggle state: %s", exc)
            print(f"Request logging {'enabled' if app.enabled.is_set() else 'disabled'}", flush=True)

        signal.signal(signal.SIGUSR1, on_toggle)
        server = ProxyServer((args.listen_host, args.listen_port), handler_for(app))
        print(f"Listening on http://{args.listen_host}:{args.listen_port} -> {args.upstream}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    except (ValueError, OSError) as exc:
        print(f"Proxy failed: {exc}", file=sys.stderr)
        return 1
    finally:
        os.ftruncate(fd, 0)
        os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
