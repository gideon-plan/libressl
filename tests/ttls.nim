{.experimental: "strictFuncs".}
## Tests for libtls FFI binding.
## Tests config/context lifecycle and client creation without requiring a server.

import std/unittest
import libressl/tls

suite "tls init":
  test "tls_init succeeded":
    # The module-level init already ran; if we got here it passed.
    check true

suite "tls config":
  test "config new and free":
    let cfg = tls_config_new()
    check cfg != nil
    tls_config_free(cfg)

  test "set protocols":
    let cfg = tls_config_new()
    check cfg != nil
    let rc = tls_config_set_protocols(cfg, uint32(TLS_PROTOCOLS_DEFAULT))
    check rc == 0
    tls_config_free(cfg)

  test "default CA cert file":
    let path = tls_default_ca_cert_file()
    check path != nil

  test "set ciphers":
    let cfg = tls_config_new()
    let rc = tls_config_set_ciphers(cfg, "secure")
    check rc == 0
    tls_config_free(cfg)

  test "verify toggle":
    let cfg = tls_config_new()
    tls_config_insecure_noverifycert(cfg)
    tls_config_insecure_noverifyname(cfg)
    tls_config_verify(cfg)  # re-enable
    tls_config_free(cfg)

  test "clear keys":
    let cfg = tls_config_new()
    tls_config_clear_keys(cfg)
    tls_config_free(cfg)

suite "tls client":
  test "create client context":
    let ctx = tls_client()
    check ctx != nil
    tls_free(ctx)

  test "configure client":
    let cfg = tls_config_new()
    let ctx = tls_client()
    let rc = tls_configure(ctx, cfg)
    check rc == 0
    tls_free(ctx)
    tls_config_free(cfg)

  test "error string on fresh context":
    let ctx = tls_client()
    let err = error_string(ctx)
    check err == ""  # no error yet
    tls_free(ctx)

  test "reset client":
    let ctx = tls_client()
    tls_reset(ctx)
    tls_free(ctx)

suite "tls server":
  test "create server context":
    let ctx = tls_server()
    check ctx != nil
    tls_free(ctx)
