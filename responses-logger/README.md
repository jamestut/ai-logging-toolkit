# Responses Logger

Responses Logger is an HTTP proxy for the Responses API that records requests and responses by session and thread. It forwards the original request body to an upstream endpoint and supports both JSON and streaming responses.

## Start the proxy

The program uses the Python 3 standard library and requires a Unix-like system with `fcntl` and `SIGUSR1` support. Start it with the complete upstream Responses endpoint and a directory for logs:

```sh
python3 responses_logger.py --upstream https://api.openai.com/v1/responses --log-dir ./logs
```

By default, the proxy listens at `http://127.0.0.1:8000`. Configure your client to send `POST` requests to `http://127.0.0.1:8000/v1/responses` and supply its normal upstream authorization header. Each request must include exactly one `session-id` and one `thread-id` header, both valid UUIDv7 values, and a JSON object as its body. Use the same ID for both headers for a root thread. Other thread IDs are stored under the same session.

The proxy supports HTTP requests only. It rejects WebSocket upgrades and compressed request bodies. It forwards requests to the exact path in `--upstream`, and combines any upstream and incoming query parameters.

Stop the proxy with Ctrl+C. Only one proxy can use a given log directory at a time.

## Logs

The log directory contains `program.log` and a directory for each session. Within a session, the root thread is named `root`, and other threads have their own directories. Directory names contain the UUIDv7 timestamp in UTC and the last eight hexadecimal digits of the ID. Each logged request gets a numbered file such as `00001.rlog`, including requests with the same turn ID and retries.

Each request log contains request headers, a request body representation, log metadata, response status and headers, and the response body. If a request's input list extends the previous input, the log stores a reference to the last full request and only the added input items. An unchanged input produces an empty delta. Delta logs do not record changes to other request body fields. Keep the earlier files to reconstruct the input. For streaming responses, the log stores the `response.completed` event rather than the entire event stream. A response without a valid completion event, or a non-streaming response that is not valid JSON, is forwarded but does not produce a request log. Check `program.log` for warnings and errors.

Request logs include headers and bodies, which can contain authorization credentials and sensitive conversation data. Protect the log directory accordingly. Request log files are created with owner-only permissions.

## Toggle request logging

To start with request logging disabled, add `--no-log`. To toggle it while the proxy is running, use the same log directory:

```sh
python3 responses_logger.py toggle ./logs
```

The toggle affects requests that start after the change. The proxy continues forwarding requests and writing `program.log` while request logging is disabled.

## Options

| Option | Description |
| --- | --- |
| `-u`, `--upstream` | Required. Complete HTTP or HTTPS upstream endpoint URL. |
| `-l`, `--log-dir` | Required. Directory for request and program logs. Created if needed. |
| `-b`, `--listen-host` | Listen address. Default: `127.0.0.1`. |
| `-p`, `--listen-port` | Listen port. Default: `8000`. |
| `-n`, `--no-log` | Start with request logging disabled. |
| `-t`, `--timeout` | Upstream socket timeout in seconds. By default, no timeout is set. |
| `-s`, `--chunk-size` | Response read chunk size in bytes. Default: `8192`. |
| `--cache-minutes` | Idle timeout for cached thread state. Default: `30` minutes. State is restored from logs when needed. |
| `-v`, `--verbose` | Print HTTP request messages to standard error. |

Run `python3 responses_logger.py --help` for the command-line help.
