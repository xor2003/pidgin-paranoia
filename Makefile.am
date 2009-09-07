SUBDIRS = tools po

ACLOCAL_AMFLAGS = -I m4

paranoia_LTLIBRARIES = paranoia.la

paranoiadir = $(PURPLE_LIBDIR)/purple-2

paranoia_la_LDFLAGS = -module -avoid-version

paranoia_la_LIBADD = $(GLIB_LIBS)

paranoia_la_SOURCES = \
	keygen.h \
	keygen.c \
	otperror.h \
	libotp.h \
	libotp-internal.h \
	libotp.c \
	key_management.h \
	key_management.c \
	paranoia.c

paranoia_la_CPPFLAGS = \
	-DVERSION=\"$(VERSION)\" \
	-DLIBDIR=\"$(PURPLE_LIBDIR)/purple-2\" \
	-DDATADIR=\"$(PURPLE_DATADIR)\" \
	-DLOCALEDIR=\"$(PURPLE_DATADIR)/locale\" \
	$(GLIB_CFLAGS) \
	$(PURPLE_CFLAGS)

BUILT_SOURCES = paranoia_config.h

$(OBJECTS): $(BUILT_SOURCES)

paranoia_config.h: pre_config.h
	$(sedpath) 's/\#define PACKAGE/\#define PARANOIA/g' pre_config.h > $@

EXTRA_DIST = \
	INFO

DISTCLEANFILES= \
	paranoia_config.h

MAINTAINERCLEANFILES = \
	Makefile.in pre_config.h.in aclocal.m4 \
	intltool-extract.in intltool-update.in intltool-merge.in \
	configure depcomp compile missing install-sh ltmain.sh \
	config.guess config.sub

