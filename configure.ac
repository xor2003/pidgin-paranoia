#
# Pidgin-Paranoia build script
# by Simon Wenner
# Inspired by the scripts of pidgin-blinklight and pidgin-encryption, thanks!
#

# Autoconf initialization
AC_INIT(pidgin-paranoia, 0.3.90, [http://pidgin-paranoia.sf.net/])

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
AM_INIT_AUTOMAKE

#
# Check for tools we need
#
AM_PROG_CC_STDC
AM_PROG_CC_C_O
CFLAGS+=" -Wall -Werror"
AC_CHECK_LIB(m, cos)
AC_PATH_PROG(sedpath, sed)
AM_PROG_LIBTOOL
LIBTOOL+=" --silent"

#
# Internationalisation stuff
#
AC_PROG_INTLTOOL
GETTEXT_PACKAGE=$PACKAGE
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, ["$GETTEXT_PACKAGE"], [0.16])
ALL_LINGUAS="de fr"
AM_GLIB_GNU_GETTEXT

#
# Additional paranoia_config.h entries
#
AC_DEFINE_UNQUOTED(PARANOIA_WEBSITE, 
    "http://pidgin-paranoia.sourceforge.net/", 
    [Pidgin-Paranoia's Website])
AC_DEFINE_UNQUOTED(PARANOIA_AUTHORS, 
    "Simon Wenner <simon@wenner.ch> Christian Wäckerlin <christian@waeckerlin.com>", 
    [Pidgin-Paranoia's Authors])
AC_DEFINE_UNQUOTED(PARANOIA_ID, 
    "core-paranoia", 
    [Pidgin-Paranoia Plugin ID])

#
# Check for glib-2.0
#
PKG_CHECK_MODULES(GLIB,
  [  glib-2.0 >= 2.16,
     gthread-2.0 >= 2.10,
     gio-2.0 >= 2.16
  ]
)

#
# Check for libpurple
#
PKG_CHECK_MODULES(PURPLE, purple >= 2.2.0,, AC_MSG_ERROR([
*** LibPurple >= 2.2.0 is required to build pidgin-paranoia.
*** The purple header files are available at http://www.pidgin.im/.]))

# Alternative:
#AM_PATH_PURPLE(2.2.0,, AC_MSG_ERROR([
#*** LibPurple 2.2.0 is required to build pidgin-paranoia.
#*** Available at http://www.pidgin.im/.]))

#
# Finish up
#

AM_CONFIG_HEADER(pre_config.h)

AC_OUTPUT([
	Makefile
	VERSION
	tools/Makefile
	po/Makefile.in
])

echo;
echo Configuration complete
echo;
echo Type make to compile
echo Thank you for using pidgin-paranoia
echo;
