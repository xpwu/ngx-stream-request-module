#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([stmclient], [VERSION], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE
# AC_CONFIG_SRCDIR([STMClient.h])
# AC_CONFIG_HEADERS([config.h])

AM_CONDITIONAL([MACOS], [test "x$(uname -s)" = "xDarwin"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_OBJCXX
AM_PROG_CC_C_O
AC_PROG_OBJC
# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.

AC_OUTPUT([Makefile])
