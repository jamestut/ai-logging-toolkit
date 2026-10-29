# [AI Logging Toolkit](https://github.com/jamestut/ai-logging-toolkit)

Tools for logging AI API traffic and inspecting `.rlog` files.

## Logging tools

Both tools write request logs as `.rlog` files.

- [Responses Logger](responses-logger/README.md) records Responses API requests by session and thread. It stores request deltas and the completed response event.
- [SSE Proxy](sse-proxy/README.md) records HTTP requests and response streams, including SSE events.

## Inspect logs

[Rlog Viewer](https://github.com/jamestut/vscode-rlog-viewer) is a VS Code extension to make inspecting `.rlog` files from either proxy easier. It provides section highlighting, folding, and formatted JSON views.
