import concurrent.futures
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "responses_logger.py"
spec = importlib.util.spec_from_file_location("responses_logger", PROGRAM)
proxy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = proxy
spec.loader.exec_module(proxy)


def make_id(suffix):
    millis = 1760000000000
    # UUIDv7 stores the timestamp, version, and variant in these high bits.
    return str(uuid.UUID(int=(millis << 80) | (7 << 76) | (2 << 62) | suffix))


SESSION = make_id(100)
THREAD = make_id(101)


def request_body(items, turn, case="sse"):
    return {"model": case, "input": items, "client_metadata": {"turn_id": turn}}


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        raw = self.rfile.read(length)
        data = json.loads(raw)
        with self.server.lock:
            self.server.received.append((self.path, dict(self.headers), data))
        case = data["model"]
        # Both response types intentionally use the other type's content type.
        if case == "json":
            payload = json.dumps({"id": "json-response", "output": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b'event: response.created\ndata: {"type":"response.created"}\n\n')
        self.wfile.flush()
        if case == "held":
            self.server.started.set()
            self.server.release.wait(5)
        if case != "incomplete":
            self.wfile.write(b'event: response.completed\ndata: {"type":"response.completed",\ndata: "response":{"id":"done"}}\n\n')
            self.wfile.flush()
        self.close_connection = True


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class ProxyIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="responses-logger-test-")
        self.logdir = Path(self.tmp.name) / "logs"
        self.upstream = Server(("127.0.0.1", 0), Upstream)
        self.upstream.lock = threading.Lock()
        self.upstream.received = []
        self.upstream.started = threading.Event()
        self.upstream.release = threading.Event()
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()
        self.start_proxy()

    def start_proxy(self, extra=()):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.process = subprocess.Popen([
            sys.executable, str(PROGRAM), "--upstream",
            f"http://127.0.0.1:{self.upstream.server_port}/unusual/endpoint?fixed=1",
            "--log-dir", str(self.logdir), "--listen-port", str(self.port), *extra,
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready, _, _ = select.select([self.process.stdout], [], [], 5)
        if not ready:
            self.process.kill()
            self.fail("Proxy did not start")
        line = self.process.stdout.readline()
        if "Listening on" not in line:
            self.fail(f"Proxy failed to start: {line} {self.process.stderr.read()}")

    def stop_proxy(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
        else:
            self.process.communicate()

    def tearDown(self):
        self.upstream.release.set()
        self.stop_proxy()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.upstream_thread.join(timeout=5)
        self.tmp.cleanup()

    def send(self, body=None, *, session=SESSION, thread=THREAD, path="/v1/responses", method="POST", extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        data = json.dumps(body if body is not None else request_body([], "a")).encode()
        headers = {"session-id": session, "thread-id": thread, "Content-Type": "application/json", "Authorization": "Bearer test-secret"}
        if extra:
            headers.update(extra)
        conn.request(method, path, data, headers)
        response = conn.getresponse()
        result = (response.status, response.read())
        conn.close()
        return result

    def folder(self, session=SESSION, thread=THREAD):
        sid, session_name = proxy.uuid7(session)
        tid, thread_name = proxy.uuid7(thread)
        return self.logdir / session_name / ("root" if sid == tid else thread_name)

    def entries(self, session=SESSION, thread=THREAD):
        return proxy.log_files(self.folder(session, thread))

    def wait_for_entries(self, count, session=SESSION, thread=THREAD):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            entries = self.entries(session, thread)
            if len(entries) == count:
                return entries
            time.sleep(0.01)
        self.fail(f"Expected {count} entries, got {self.entries(session, thread)}")

    def toggle(self):
        result = subprocess.run([sys.executable, str(PROGRAM), "toggle", str(self.logdir)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_routes_identifiers_and_uncompressed_forwarding(self):
        """Reject unsupported requests and ask the upstream for uncompressed responses."""
        self.assertEqual(self.send(path="/other")[0], 404)
        self.assertEqual(self.send(method="GET")[0], 405)
        self.assertEqual(self.send(session="not-a-uuid")[0], 400)
        self.assertEqual(self.send(session=str(uuid.uuid4()))[0], 400)
        self.assertEqual(self.send(extra={"Content-Encoding": "gzip"})[0], 400)
        self.assertEqual(self.send(extra={"Upgrade": "websocket", "Connection": "Upgrade"})[0], 400)
        status, payload = self.send(path="/v1/responses?dynamic=2", extra={"Accept-Encoding": "gzip"})
        self.assertEqual(status, 200)
        self.assertIn(b"response.completed", payload)
        path, headers, _ = self.upstream.received[-1]
        self.assertEqual(path, "/unusual/endpoint?fixed=1&dynamic=2")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        log = self.wait_for_entries(1)[0][2].read_text()
        self.assertIn("Authorization: Bearer test-secret", log)
        self.assertIn('"type":"response.completed"', log)
        self.assertIn("Request rejected", (self.logdir / "program.log").read_text())

    def test_deltas_restart_and_cache_expiry(self):
        """Record same-turn requests and reconstruct input after cache expiry and restart."""
        self.stop_proxy()
        self.start_proxy(("--cache-minutes", "0.0002"))
        for count, body in enumerate((request_body(["A", "B"], "1"), request_body(["A", "B", "C"], "2"), request_body(["A", "B", "C", "D"], "2"), request_body(["A", "B", "C", "D"], "2")), 1):
            self.assertEqual(self.send(body)[0], 200)
            self.wait_for_entries(count)
        entries = self.wait_for_entries(4)
        self.assertEqual([e[2].name for e in entries], ["00001.rlog", "00002.rlog", "00003.rlog", "00004.rlog"])
        self.assertEqual(proxy.body_from_log(entries[2][2])[1], {"continuation": 1, "input_delta": ["D"]})
        self.assertEqual(proxy.body_from_log(entries[3][2])[1], {"continuation": 1, "input_delta": []})
        self.stop_proxy()
        self.start_proxy(("--cache-minutes", "0.0002"))
        time.sleep(0.02)
        self.assertEqual(self.send(request_body(["A", "B", "C", "D", "E"], "4"))[0], 200)
        entry = self.wait_for_entries(5)[-1]
        self.assertEqual(proxy.body_from_log(entry[2])[1], {"continuation": 1, "input_delta": ["E"]})
        self.assertEqual(self.send(request_body(["X", "Y", "Z"], "5"))[0], 200)
        self.wait_for_entries(6)
        self.assertEqual(self.send(request_body(["X", "Y", "Z"], "5"))[0], 200)
        entries = self.wait_for_entries(7)
        self.assertEqual(proxy.body_from_log(entries[-2][2])[1]["input"], ["X", "Y", "Z"])
        self.assertEqual(proxy.body_from_log(entries[-1][2])[1], {"continuation": 6, "input_delta": []})
        self.stop_proxy()
        self.start_proxy()
        self.assertEqual(self.send(request_body(["X", "Y", "Z", "W"], "6"))[0], 200)
        entry = self.wait_for_entries(8)[-1]
        self.assertEqual(proxy.body_from_log(entry[2])[1], {"continuation": 6, "input_delta": ["W"]})

    def test_restore_legacy_retry_files(self):
        self.assertEqual(self.send(request_body(["A"], "1"))[0], 200)
        first = self.wait_for_entries(1)[0][2]
        self.stop_proxy()
        first.with_name("00001-01.rlog").write_text(first.read_text())
        self.start_proxy()
        self.assertEqual(self.send(request_body(["A", "B"], "1"))[0], 200)
        entries = self.wait_for_entries(3)
        self.assertEqual(entries[-1][2].name, "00002.rlog")
        self.assertEqual(proxy.body_from_log(entries[-1][2])[1], {"continuation": 1, "input_delta": ["B"]})

    def test_incomplete_stream_and_toggle(self):
        """Skip incomplete streams and honor changes to request logging."""
        self.assertEqual(self.send(request_body([1], "turn", "incomplete"))[0], 200)
        self.assertEqual(self.entries(), [])
        self.assertIn("disabled", self.toggle())
        self.assertEqual(self.send(request_body([1], "turn"))[0], 200)
        self.assertEqual(self.entries(), [])
        self.assertIn("enabled", self.toggle())
        self.assertEqual(self.send(request_body([1], "turn"))[0], 200)
        self.assertEqual(self.wait_for_entries(1)[0][2].name, "00001.rlog")
        self.assertIn("response.completed missing", (self.logdir / "program.log").read_text())

    def test_json_and_root_directory(self):
        """Detect mislabeled JSON and log a root thread in its root directory."""
        status, payload = self.send(request_body([1], "turn", "json"), thread=SESSION)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["id"], "json-response")
        entry = self.wait_for_entries(1, thread=SESSION)[0][2]
        self.assertEqual(entry.parent.name, "root")
        self.assertIn('"id":"json-response"', entry.read_text())

    def test_stream_forwarded_before_completion(self):
        """Forward streaming data promptly and keep the in-flight logging decision."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        data = json.dumps(request_body([1], "turn", "held")).encode()
        conn.request("POST", "/v1/responses", data, {"session-id": SESSION, "thread-id": THREAD})
        response = conn.getresponse()
        self.assertTrue(self.upstream.started.wait(2))
        self.assertEqual(response.read(6), b"event:")
        self.assertEqual(self.entries(), [])
        self.assertIn("disabled", self.toggle())
        self.upstream.release.set()
        self.assertIn(b"response.completed", response.read())
        conn.close()
        self.wait_for_entries(1)
        self.assertEqual(self.send(request_body([1], "next"))[0], 200)
        self.assertEqual(len(self.entries()), 1)

    def test_parallel_threads_and_collision(self):
        """Log concurrent threads independently and reject colliding thread identities."""
        thread_ids = [make_id(i + 1000) for i in range(8)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda t: self.send(request_body([t], "turn"), thread=t)[0], thread_ids))
        self.assertEqual(results, [200] * len(thread_ids))
        for thread in thread_ids:
            self.wait_for_entries(1, thread=thread)
        # Change a UUID bit omitted from the directory name to force a collision.
        collision = str(uuid.UUID(int=uuid.UUID(THREAD).int | (1 << 64)))
        self.assertEqual(self.send(thread=THREAD)[0], 200)
        self.wait_for_entries(1)
        self.assertEqual(self.send(thread=collision)[0], 500)
        self.assertIn("collision", (self.logdir / "program.log").read_text())

    def test_corrupt_chain_returns_server_error(self):
        """Return a server error when a continuation chain cannot be reconstructed."""
        self.assertEqual(self.send(request_body(["A"], "1"))[0], 200)
        self.wait_for_entries(1)
        self.assertEqual(self.send(request_body(["A", "B"], "2"))[0], 200)
        entries = self.wait_for_entries(2)
        entries[0][2].unlink()
        self.stop_proxy()
        self.start_proxy()
        self.assertEqual(self.send(request_body(["A", "B", "C"], "3"))[0], 500)
        self.assertIn("continuation", (self.logdir / "program.log").read_text())

    def test_full_request_with_continuation_named_fields(self):
        """Treat continuation-like fields in a full request as ordinary request data."""
        body = request_body(["A"], "1")
        body.update({"continuation": 999, "input_delta": ["unrelated"]})
        self.assertEqual(self.send(body)[0], 200)
        self.wait_for_entries(1)
        self.stop_proxy()
        self.start_proxy()
        self.assertEqual(self.send(request_body(["A", "B"], "2"))[0], 200)
        entry = self.wait_for_entries(2)[-1]
        self.assertEqual(proxy.body_from_log(entry[2])[1], {"continuation": 1, "input_delta": ["B"]})


if __name__ == "__main__":
    unittest.main()
