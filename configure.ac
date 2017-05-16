dnl meson-tools

dnl Initialization
AC_INIT([meson-tools], [0.2], [Andreas Färber <andreas.faerber@web.de>])
AM_INIT_AUTOMAKE
LT_INIT

dnl Configure macros
AC_CONFIG_MACRO_DIR([m4])

LDFLAGS+=" -lcrypto"

AC_CHECK_HEADER([openssl/sha.h],
  [],
  [AC_MSG_ERROR([openssl/sha.h not found. Please, install libssl-dev.])]
  )

dnl Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  ])  

dnl Generate files
AC_OUTPUT

