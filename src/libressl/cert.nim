## X.509 certificate handling helpers for libtls.
##
## Wraps tls_peer_cert_* and tls_load_file for certificate inspection
## and loading.

{.experimental: "strictFuncs".}

import libressl/tls

# ---------------------------------------------------------------------------
# Certificate info (post-handshake)
# ---------------------------------------------------------------------------

proc peer_cert_provided*(ctx: TlsCtx): bool =
  ## Returns true if the peer provided a certificate.
  tls_peer_cert_provided(ctx) == 1

proc peer_cert_common_name*(ctx: TlsCtx): string =
  ## Get the peer certificate common name.
  let cn = tls_peer_cert_common_name(ctx)
  if cn != nil: $cn else: ""

proc peer_cert_hash*(ctx: TlsCtx): string =
  ## Get the peer certificate hash (e.g. "SHA256:...").
  let h = tls_peer_cert_hash(ctx)
  if h != nil: $h else: ""

proc peer_cert_issuer*(ctx: TlsCtx): string =
  ## Get the peer certificate issuer.
  let s = tls_peer_cert_issuer(ctx)
  if s != nil: $s else: ""

proc peer_cert_subject*(ctx: TlsCtx): string =
  ## Get the peer certificate subject.
  let s = tls_peer_cert_subject(ctx)
  if s != nil: $s else: ""

proc peer_cert_notbefore*(ctx: TlsCtx): int64 =
  ## Get the peer certificate not-before time (Unix created).
  tls_peer_cert_notbefore(ctx)

proc peer_cert_notafter*(ctx: TlsCtx): int64 =
  ## Get the peer certificate not-after time (Unix created).
  tls_peer_cert_notafter(ctx)

proc peer_cert_contains_name*(ctx: TlsCtx, name: string): bool =
  ## Check if the peer certificate contains a given name (CN or SAN).
  tls_peer_cert_contains_name(ctx, cstring(name)) == 1

proc peer_cert_chain_pem*(ctx: TlsCtx): string =
  ## Get the full peer certificate chain in PEM format.
  var len: csize_t
  let data = tls_peer_cert_chain_pem(ctx, addr len)
  if data != nil and len > 0:
    result = newString(len)
    copyMem(addr result[0], data, len)
  else:
    result = ""

# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------

proc load_cert_file*(path: string, password: string = ""): seq[byte] =
  ## Load a certificate or key file. Returns raw bytes.
  var len: csize_t
  let pw = if password.len > 0: cstring(password) else: nil
  let data = tls_load_file(cstring(path), addr len, pw)
  if data != nil and len > 0:
    result = newSeq[byte](len)
    copyMem(addr result[0], data, len)
    tls_unload_file(data, len)
  else:
    result = @[]

# ---------------------------------------------------------------------------
# Connection info
# ---------------------------------------------------------------------------

proc conn_version*(ctx: TlsCtx): string =
  ## Get the negotiated TLS version string.
  let v = tls_conn_version(ctx)
  if v != nil: $v else: ""

proc conn_cipher*(ctx: TlsCtx): string =
  ## Get the negotiated cipher suite name.
  let c = tls_conn_cipher(ctx)
  if c != nil: $c else: ""

proc conn_cipher_strength*(ctx: TlsCtx): int =
  ## Get the negotiated cipher strength in bits.
  int(tls_conn_cipher_strength(ctx))

proc conn_alpn_selected*(ctx: TlsCtx): string =
  ## Get the ALPN protocol selected during handshake.
  let a = tls_conn_alpn_selected(ctx)
  if a != nil: $a else: ""

proc conn_servername*(ctx: TlsCtx): string =
  ## Get the servername from SNI.
  let s = tls_conn_servername(ctx)
  if s != nil: $s else: ""
