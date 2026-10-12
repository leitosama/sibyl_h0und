---
name: ngfw-run-env
description: "How to run h0und and the LLM replay scripts behind the corporate NGFW"
metadata:
  node_type: memory
  type: reference
  originSessionId: 3794ccef-4486-41e5-b30f-e2427ff8250b
  modified: 2026-10-09T08:37:07.339Z
---

Behind the user's corporate NGFW, the agent needs these env vars (verified 2026-10-09):

- Runtime gRPC (`bluesec.team:443`): direct TLS is intercepted by Kaspersky and loses HTTP/2, so route through the proxy with `grpc_proxy="$HTTPS_PROXY"` (gRPC ignores uppercase `HTTPS_PROXY`), keep `SCENARIO_RUNTIME_VERIFY_TLS=true` (false opens a plaintext channel), and set `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`.
- Internal LiteLLM (`*.domain.ru`): `NO_PROXY=domain.ru` and `SSL_CERT_FILE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`; without the latter, Python fails with CERTIFICATE_VERIFY_FAILED, which shows up as "Connection error".

Models on the provider: Qwen3.8-27B, DeepSeek-V4-Flash-0731, Qwen3.5-35B-A3B, Qwen3-Coder. See [[glm-5-3-not-usable]].
