## libtls FFI binding for LibreSSL 4.2.1.
##
## Wraps the libtls API: TLS client, TLS server, configuration,
## certificate inspection, and connection management.
##
## libtls is the misuse-resistant TLS API unique to LibreSSL.
## Satellites consuming TLS through C libraries (curl, ngtcp2, libpq)
## link LibreSSL's libssl/libcrypto directly at build time and do not
## go through this module.

{.experimental: "strictFuncs".}

const TlsHdr = "tls.h"

{.emit: """
#include <tls.h>
""".}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

const
  TLS_PROTOCOL_TLSv1_2* = 1 shl 3
  TLS_PROTOCOL_TLSv1_3* = 1 shl 4
  TLS_PROTOCOLS_DEFAULT* = TLS_PROTOCOL_TLSv1_2 or TLS_PROTOCOL_TLSv1_3
  TLS_WANT_POLLIN* = -2
  TLS_WANT_POLLOUT* = -3

# ---------------------------------------------------------------------------
# Opaque types
# ---------------------------------------------------------------------------

type
  TlsCtxObj {.importc: "struct tls", header: TlsHdr, incompleteStruct.} = object
  TlsConfigObj {.importc: "struct tls_config", header: TlsHdr, incompleteStruct.} = object
  TlsCtx* = ptr TlsCtxObj
  TlsConfig* = ptr TlsConfigObj

# ---------------------------------------------------------------------------
# FFI - init / error
# ---------------------------------------------------------------------------

proc tls_init*(): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_error*(config: TlsConfig): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_error*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - config lifecycle
# ---------------------------------------------------------------------------

proc tls_config_new*(): TlsConfig {.importc, cdecl, header: TlsHdr.}
proc tls_config_free*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - config: CA / cert / key
# ---------------------------------------------------------------------------

proc tls_default_ca_cert_file*(): cstring {.importc, cdecl, header: TlsHdr.}

proc tls_config_set_ca_file*(config: TlsConfig,
  ca_file: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_ca_path*(config: TlsConfig,
  ca_path: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_ca_mem*(config: TlsConfig,
  ca: ptr uint8, len: csize_t): cint {.importc, cdecl, header: TlsHdr.}

proc tls_config_set_cert_file*(config: TlsConfig,
  cert_file: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_cert_mem*(config: TlsConfig,
  cert: ptr uint8, len: csize_t): cint {.importc, cdecl, header: TlsHdr.}

proc tls_config_set_key_file*(config: TlsConfig,
  key_file: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_key_mem*(config: TlsConfig,
  key: ptr uint8, len: csize_t): cint {.importc, cdecl, header: TlsHdr.}

proc tls_config_set_keypair_file*(config: TlsConfig,
  cert_file: cstring, key_file: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_keypair_mem*(config: TlsConfig,
  cert: ptr uint8, cert_len: csize_t,
  key: ptr uint8, key_len: csize_t): cint {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - config: protocol / cipher / verify
# ---------------------------------------------------------------------------

proc tls_config_set_protocols*(config: TlsConfig,
  protocols: uint32): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_ciphers*(config: TlsConfig,
  ciphers: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_alpn*(config: TlsConfig,
  alpn: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_config_set_verify_depth*(config: TlsConfig,
  verify_depth: cint): cint {.importc, cdecl, header: TlsHdr.}

proc tls_config_verify*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}
proc tls_config_insecure_noverifycert*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}
proc tls_config_insecure_noverifyname*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}
proc tls_config_insecure_noverifytime*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}

proc tls_config_verify_client*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}
proc tls_config_verify_client_optional*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}

proc tls_config_prefer_ciphers_client*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}
proc tls_config_prefer_ciphers_server*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}

proc tls_config_clear_keys*(config: TlsConfig) {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - context lifecycle
# ---------------------------------------------------------------------------

proc tls_client*(): TlsCtx {.importc, cdecl, header: TlsHdr.}
proc tls_server*(): TlsCtx {.importc, cdecl, header: TlsHdr.}
proc tls_configure*(ctx: TlsCtx, config: TlsConfig): cint {.importc, cdecl, header: TlsHdr.}
proc tls_reset*(ctx: TlsCtx) {.importc, cdecl, header: TlsHdr.}
proc tls_free*(ctx: TlsCtx) {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - connect / accept
# ---------------------------------------------------------------------------

proc tls_connect*(ctx: TlsCtx, host: cstring,
  port: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_connect_fds*(ctx: TlsCtx, fd_read: cint, fd_write: cint,
  servername: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_connect_socket*(ctx: TlsCtx, s: cint,
  servername: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_connect_servername*(ctx: TlsCtx, host: cstring, port: cstring,
  servername: cstring): cint {.importc, cdecl, header: TlsHdr.}

proc tls_accept_socket*(ctx: TlsCtx, cctx: ptr TlsCtx,
  socket: cint): cint {.importc, cdecl, header: TlsHdr.}
proc tls_accept_fds*(ctx: TlsCtx, cctx: ptr TlsCtx,
  fd_read: cint, fd_write: cint): cint {.importc, cdecl, header: TlsHdr.}

proc tls_handshake*(ctx: TlsCtx): cint {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - read / write / close
# ---------------------------------------------------------------------------

proc tls_read*(ctx: TlsCtx, buf: pointer,
  buflen: csize_t): int {.importc, cdecl, header: TlsHdr.}
proc tls_write*(ctx: TlsCtx, buf: pointer,
  buflen: csize_t): int {.importc, cdecl, header: TlsHdr.}
proc tls_close*(ctx: TlsCtx): cint {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - peer certificate inspection
# ---------------------------------------------------------------------------

proc tls_peer_cert_provided*(ctx: TlsCtx): cint {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_contains_name*(ctx: TlsCtx,
  name: cstring): cint {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_common_name*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_hash*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_issuer*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_subject*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_notbefore*(ctx: TlsCtx): int64 {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_notafter*(ctx: TlsCtx): int64 {.importc, cdecl, header: TlsHdr.}
proc tls_peer_cert_chain_pem*(ctx: TlsCtx,
  len: ptr csize_t): ptr uint8 {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - connection info
# ---------------------------------------------------------------------------

proc tls_conn_alpn_selected*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_conn_cipher*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_conn_cipher_strength*(ctx: TlsCtx): cint {.importc, cdecl, header: TlsHdr.}
proc tls_conn_servername*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}
proc tls_conn_session_resumed*(ctx: TlsCtx): cint {.importc, cdecl, header: TlsHdr.}
proc tls_conn_version*(ctx: TlsCtx): cstring {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# FFI - file loading
# ---------------------------------------------------------------------------

proc tls_load_file*(file: cstring, len: ptr csize_t,
  password: cstring): ptr uint8 {.importc, cdecl, header: TlsHdr.}
proc tls_unload_file*(buf: ptr uint8, len: csize_t) {.importc, cdecl, header: TlsHdr.}

# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

let tlsReady = tls_init()
assert tlsReady == 0, "tls_init failed"

# ---------------------------------------------------------------------------
# Nim-level helpers
# ---------------------------------------------------------------------------

proc error_string*(ctx: TlsCtx): string =
  ## Get the error string for a TLS context.
  let e = tls_error(ctx)
  if e != nil: $e else: ""

proc config_error_string*(config: TlsConfig): string =
  ## Get the error string for a TLS config.
  let e = tls_config_error(config)
  if e != nil: $e else: ""
