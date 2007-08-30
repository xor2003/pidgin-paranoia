#
# This script was stolen from pidgin-blinklight and most of
# their configure script was ripped from gaim or the
# gaim-encryption configure script, thanks guys ;)
#

AC_INIT([pidgin-paranoia], [0.1.0], [there are no bugs!])
AC_CANONICAL_SYSTEM
AC_GNU_SOURCE
AM_CONFIG_HEADER(pre_config.h)

#
# The third argument to AM_INIT_AUTOMAKE surpresses the PACKAGE and
# VERSION macors
#
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION, 'no-define')

AC_PREREQ([2.50])

AC_PATH_PROG(sedpath, sed)
AC_DISABLE_STATIC

#
# Setup libtool
#

AM_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"

#
# Additional paranoia_config.h entires!
#

AC_DEFINE_UNQUOTED(OTP_WEBSITE, "http://sourceforge.net/projects/pidgin-paranoia", [Pidgin-Paranoia's Website])
AC_DEFINE_UNQUOTED(OTP_AUTHORS, "Simon Wenner <simon@wenner.ch> Christian Wäckerlin <christian@waeckerlin.com>", [Pidgin-Paranoia's Authors])
AC_DEFINE_UNQUOTED(OTP_ID, "core-paranoia", [Pidgin-Paranoia Plugin ID])

# Swich for realotp support: 
# See: http://sourceware.org/autobook/autobook/autobook_283.html#SEC283
AC_MSG_CHECKING(for realotp support)
AC_ARG_ENABLE(otp,
[  --disable-otp       Enable realotp support.
],
[
  if test "$withval"; then
    AC_DEFINE([NOOTP],[1],[Define if otp support is disabled in paranoia.c])
  fi
],[
  AC_MSG_RESULT(no)
])

#
# Look for the C compiler
#
CFLAGS_save="$CFLAGS"
AC_PROG_CC_STDC
CFLAGS="$CFLAGS_save"

CFLAGS="$CFLAGS -Wall"

AC_SUBST(CFLAGS)

#
# Check for pidgin (libpurple)
#

PKG_CHECK_MODULES(PURPLE, purple,
[
	AC_DEFINE(HAVE_PURPLE, 1, [Define if we've found purple.])
])

AC_SUBST(PURPLE)
PURPLE_LIBDIR=`pkg-config --variable=libdir purple`
PURPLE_DATADIR=`pkg-config --variable=datadir purple`
AC_SUBST(PURPLE_LIBDIR)
AC_SUBST(PURPLE_DATADIR)

#
# check for glib
#

AM_PATH_GLIB_2_0(2.0.0,,AC_MSG_ERROR([
*** GLib 2.0 is required to build pidgin-paranoia; please make sure you have the.
*** GLib development headers installed. The latest version of GLib is always
*** available at http://www.gtk.org/.]))

AC_SUBST(GLIB_CFLAGS)

#
# Finish up
#

AC_OUTPUT([Makefile
	   VERSION
	  ])

echo;
echo Configuration complete
echo;
echo Type make to compile
echo Thank you for using pidgin-paranoia
echo;
