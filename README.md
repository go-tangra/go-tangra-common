# go-tangra-common

Shared utilities and infrastructure library for the Go-Tangra ecosystem. Provides foundational cross-cutting concerns used by all platform services.

## Packages

### `crypto/`
AES-256-GCM authenticated encryption for sensitive data (credentials, task payloads). Backward-compatible — gracefully handles unencrypted legacy data.

```go
enc := crypto.NewEncryptor("my-secret-key")
ciphertext, _ := enc.Encrypt("sensitive-data")   // "enc:base64..."
plaintext, _ := enc.Decrypt(ciphertext)
```

### `eventbus/`
Flexible event-driven communication system with:
- Multiple isolated event buses (global + named)
- Synchronous and asynchronous publishing
- Once-only handlers, middleware (logging, recovery, timeout, retry)
- Thread-safe operations

Predefined event types for email, user, task, and system lifecycle.

### `middleware/audit/`
gRPC server-side audit logging middleware:
- Captures operation, client identity, latency, success/failure
- Integrates with mTLS for client certificate info extraction
- ECDSA signature generation for audit log integrity verification
- SHA-256 hashing for tamper detection

### `middleware/mtls/`
Mutual TLS client certificate validation middleware for gRPC:
- Public endpoint bypass (configurable)
- Trusted organization/OU validation
- Certificate validity date checking
- Client info extraction and context passing

### `service/`
Service discovery naming conventions following `gotangra/{serviceName}` pattern.

### `utils/slice/`
Generic slice utilities: merge, deduplicate, intersect, unique.

## Protobuf

Defines the **Module Registration Service** (`protos/common/service/v1/module_registration.proto`) for dynamic module registration, heartbeat, and discovery.

## Dependencies

- `github.com/go-kratos/kratos/v2` — Microservice framework
- `google.golang.org/grpc` — gRPC
- `google.golang.org/protobuf` — Protocol Buffers

## Build

```bash
# Generate protobuf code
buf generate

# Run tests
go test ./...
```
