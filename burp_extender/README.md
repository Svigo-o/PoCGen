# Burp Extender: LLM Proxy Controller

This Burp extension exposes a minimal HTTP API to integrate with a model-driven workflow:

- /list: enumerate captured requests (id, method, url, host, port, https)
- /get_raw?id=N: return raw request bytes for item N
- /replay_raw?host=...&port=...&https=true|false: post raw bytes to replay through Burp

## Build & Load

1. Download Burp Extender API JAR (burp-extender-api.jar) or use Burp's provided classpath.
2. Compile this file into a JAR including this class.
3. Load the JAR in Burp: Extender -> Extensions -> Add -> Select JAR.

The extension starts a local HTTP server on 127.0.0.1:7001.

## Security
- This demo exposes an unauthenticated local API. Restrict access to localhost and use in controlled environments only.
- Raw replay may target arbitrary hosts; implement allowlists and rate-limits for safety.
