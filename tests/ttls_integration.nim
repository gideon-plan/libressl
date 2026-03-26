## Integration tests for libtls: TLS client/server over socketpair.
##
## Uses a thread for the server side to avoid blocking deadlocks.

import std/[unittest, os, osproc, tempfiles]
import libressl/tls
import libressl/cert

# ---------------------------------------------------------------------------
# Self-signed cert generation
# ---------------------------------------------------------------------------

proc generate_self_signed(cert_path, key_path: string) =
  let cmd = "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 " &
    "-keyout " & key_path & " -out " & cert_path &
    " -days 1 -nodes -subj '/CN=localhost' 2>/dev/null"
  let rc = execCmd(cmd)
  assert rc == 0, "Failed to generate self-signed cert"

# ---------------------------------------------------------------------------
# socketpair FFI
# ---------------------------------------------------------------------------

proc c_socketpair(domain: cint, typ: cint, protocol: cint,
                  sv: ptr array[2, cint]): cint
  {.importc: "socketpair", header: "<sys/socket.h>".}

const
  AF_UNIX = 1.cint
  SOCK_STREAM = 1.cint

proc make_socketpair(): (cint, cint) =
  var fds: array[2, cint]
  let rc = c_socketpair(AF_UNIX, SOCK_STREAM, 0.cint, addr fds)
  assert rc == 0, "socketpair failed"
  (fds[0], fds[1])

# ---------------------------------------------------------------------------
# Server thread
# ---------------------------------------------------------------------------

type
  ServerArgs = object
    fd: cint
    cert_path: string
    key_path: string
    received: string
    reply: string
    ok: bool

proc server_thread(args: ptr ServerArgs) {.thread.} =
  let srv_cfg = tls_config_new()
  discard tls_config_set_keypair_file(srv_cfg, cstring(args.cert_path), cstring(args.key_path))

  let srv_ctx = tls_server()
  discard tls_configure(srv_ctx, srv_cfg)

  var accepted_ctx: TlsCtx
  discard tls_accept_fds(srv_ctx, addr accepted_ctx, args.fd, args.fd)

  # Handshake
  var hs: cint
  for _ in 0 ..< 1000:
    hs = tls_handshake(accepted_ctx)
    if hs == 0: break
  if hs != 0:
    args.ok = false
    return

  # Read
  var buf: array[256, byte]
  var n = tls_read(accepted_ctx, addr buf[0], csize_t(256))
  while n == TLS_WANT_POLLIN or n == TLS_WANT_POLLOUT:
    n = tls_read(accepted_ctx, addr buf[0], csize_t(256))

  if n > 0:
    args.received = newString(n)
    copyMem(addr args.received[0], addr buf[0], n)

  # Write reply
  let reply = "hello from server"
  args.reply = reply
  var w = tls_write(accepted_ctx, unsafeAddr reply[0], csize_t(reply.len))
  while w == TLS_WANT_POLLOUT or w == TLS_WANT_POLLIN:
    w = tls_write(accepted_ctx, unsafeAddr reply[0], csize_t(reply.len))

  discard tls_close(accepted_ctx)
  tls_free(accepted_ctx)
  tls_free(srv_ctx)
  tls_config_free(srv_cfg)
  args.ok = true

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

suite "tls client/server integration":
  var cert_path, key_path: string
  var cert_dir: string

  setup:
    cert_dir = createTempDir("tls_test_", "")
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"
    generate_self_signed(cert_path, key_path)

  teardown:
    removeFile(cert_path)
    removeFile(key_path)
    removeDir(cert_dir)

  test "handshake, data exchange, cert inspection":
    let (fd_client, fd_server) = make_socketpair()

    # Start server thread
    var args = ServerArgs(
      fd: fd_server,
      cert_path: cert_path,
      key_path: key_path,
      ok: false
    )
    var thr: Thread[ptr ServerArgs]
    createThread(thr, server_thread, addr args)

    # Client config
    let cli_cfg = tls_config_new()
    tls_config_insecure_noverifycert(cli_cfg)
    tls_config_insecure_noverifyname(cli_cfg)

    let cli_ctx = tls_client()
    check tls_configure(cli_ctx, cli_cfg) == 0

    # Connect
    check tls_connect_fds(cli_ctx, fd_client, fd_client, "localhost") == 0

    # Handshake
    var hs: cint
    for _ in 0 ..< 1000:
      hs = tls_handshake(cli_ctx)
      if hs == 0: break
    check hs == 0

    # Connection info
    let ver = conn_version(cli_ctx)
    check ver.len > 0

    let cipher_name = conn_cipher(cli_ctx)
    check cipher_name.len > 0

    let strength = conn_cipher_strength(cli_ctx)
    check strength > 0

    # Write to server
    let msg = "hello from client"
    var written = tls_write(cli_ctx, unsafeAddr msg[0], csize_t(msg.len))
    while written == TLS_WANT_POLLOUT or written == TLS_WANT_POLLIN:
      written = tls_write(cli_ctx, unsafeAddr msg[0], csize_t(msg.len))
    check written == msg.len

    # Read server reply
    var buf: array[256, byte]
    var n = tls_read(cli_ctx, addr buf[0], csize_t(256))
    while n == TLS_WANT_POLLIN or n == TLS_WANT_POLLOUT:
      n = tls_read(cli_ctx, addr buf[0], csize_t(256))
    check n > 0
    var received = newString(n)
    copyMem(addr received[0], addr buf[0], n)
    check received == "hello from server"

    # Peer cert inspection
    check peer_cert_provided(cli_ctx)
    check peer_cert_common_name(cli_ctx) == "localhost"
    check peer_cert_hash(cli_ctx).len > 0
    check peer_cert_subject(cli_ctx).len > 0
    check peer_cert_issuer(cli_ctx).len > 0

    discard tls_close(cli_ctx)
    tls_free(cli_ctx)
    tls_config_free(cli_cfg)

    joinThread(thr)
    check args.ok
    check args.received == "hello from client"
