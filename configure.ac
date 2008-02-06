#
# Pidgin-Paranoia build script
# by Simon Wenner
# Inspired by the scripts of pidgin-blinklight and pidgin-encryption, thanks!
#

# Autoconf initialization
AC_INIT(pidgin-paranoia, 0.2.0, [http://pidgin-paranoia.sf.net/])

# Required autoconf version
AC_PREREQ([2.50])

# This macro determines the type of the build, host and target systems and sets 
# the output variables `build', `host' and `target', amongst other more obscure 
# variables.
AC_CANONICAL_SYSTEM

# changes the default behavior of AC_PROG_LIBTOOL so that static libraries will 
# not be built by default. (*.a files)
AC_DISABLE_STATIC

# Automake standard initialization
AM_INIT_AUTOMAKE()

#
# Check for tools we need
#
AM_PROG_CC_STDC
CFLAGS+=" -Wall"
AC_CHECK_LIB(m, cos)
AC_PATH_PROG(sedpath, sed)
AM_PROG_LIBTOOL
LIBTOOL+=" --silent"

#TODO: AM_GLIB_GNU_GETTEXT
#TODO: AC_PROG_INTLTOOL

#
# Additional paranoia_config.h entries
#
AC_DEFINE_UNQUOTED(PARANOIA_WEBSITE, "http://pidgin-paranoia.sourceforge.net/", [Pidgin-Paranoia's Website])
AC_DEFINE_UNQUOTED(PARANOIA_AUTHORS, "Simon Wenner <simon@wenner.ch> Christian Wäckerlin <christian@waeckerlin.com>", [Pidgin-Paranoia's Authors])
AC_DEFINE_UNQUOTED(PARANOIA_ID, "core-paranoia", [Pidgin-Paranoia Plugin ID])

#
# Check for glib2.0
#
AM_PATH_GLIB_2_0(2.12.0,, AC_MSG_ERROR([
*** GLib 2.12.0 is required to build pidgin-paranoia;  The latest version of 
*** GLib is always available at http://www.gtk.org/.]))

PKG_CHECK_MODULES(GTHREAD, gthread-2.0,, [AC_MSG_ERROR([unable to find the GThread library])])
PKG_CHECK_MODULES(GOBJECT, gobject-2.0,, [AC_MSG_ERROR([unable to find the GObject library])])

GLIB_LIBS+="`pkg-config --libs gthread-2.0 gobject-2.0`"
GLIB_CFLAGS+="`pkg-config --cflags gthread-2.0 gobject-2.0`"

#
# Check for libpurple
#
PKG_CHECK_MODULES(PURPLE, purple >= 2.2.0,, AC_MSG_ERROR([
*** Lib Purple >= 2.2.0 is required to build pidgin-paranoia.
*** The purple header files are available at http://www.pidgin.im/.]))

# Maybe a better solution in the future:
#AM_PATH_PURPLE(2.2.0,, AC_MSG_ERROR([
#*** LibPurple 2.2.0 is required to build pidgin-paranoia.
#*** Available at http://www.pidgin.im/.]))

PURPLE_LIBDIR=`pkg-config --variable=libdir purple`
PURPLE_DATADIR=`pkg-config --variable=datadir purple`
AC_SUBST(PURPLE_LIBDIR)
AC_SUBST(PURPLE_DATADIR)

#
# Finish up
#

AM_CONFIG_HEADER(pre_config.h)

AC_OUTPUT([
	Makefile
	VERSION
	tools/Makefile
	])

echo;
echo Configuration complete
echo;
echo Type make to compile
echo Thank you for using pidgin-paranoia
echo;
