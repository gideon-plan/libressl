switch("path", "src")
switch("threads", "on")
switch("outdir", ".out")

# Vendored LibreSSL (4.2.1)
const libresslDir = thisDir() & "/vendor/libressl"
switch("passC", "-I" & libresslDir & "/include")
switch("passL", libresslDir & "/lib/libtls.a")
switch("passL", libresslDir & "/lib/libssl.a")
switch("passL", libresslDir & "/lib/libcrypto.a")
switch("passL", "-lpthread")

when file_exists("nimble.paths"):
  include "nimble.paths"
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
