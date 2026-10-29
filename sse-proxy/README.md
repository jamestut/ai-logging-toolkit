# SSE Proxy

SSE Proxy forwards HTTP requests to an HTTP or HTTPS upstream and can record requests and response streams in `.rlog` files.

## Start the proxy

The proxy uses the Python 3 standard library and requires a Unix-like system with `fcntl` and `SIGUSR1` support. Specify an upstream URL and a log directory:

```sh
python3 sse_proxy.py --upstream https://api.openai.com --log-dir ./logs
```

By default, the proxy listens at `http://127.0.0.1:8000` and forwards request paths to the upstream. Configure your client to use that address and supply its normal authorization headers. Stop the proxy with Ctrl+C.

The inbound connection uses HTTP. The proxy disables certificate verification for HTTPS upstreams.

## Logs

Each request gets a separate `.rlog` file containing request and upstream headers, request body, response headers, and the response stream. Logs can contain credentials and sensitive conversation data, so protect the log directory.

Logging is disabled when `--log-dir` is omitted. To start with logging disabled while keeping a log directory configured, add `--no-log`. Toggle request logging while the proxy runs by using the same log directory:

```sh
python3 sse_proxy.py toggle ./logs
```

The toggle affects requests that start afterward. Run `python3 sse_proxy.py --help` for all options.
