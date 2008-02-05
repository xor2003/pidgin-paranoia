SUBDIRS = tools

paranoia_LTLIBRARIES = paranoia.la

paranoiadir = $(PURPLE_LIBDIR)/purple-2

paranoia_la_LDFLAGS = -module -avoid-version

paranoia_la_LIBADD = $(GLIB_LIBS)

paranoia_la_SOURCES = \
	keygen.h \
	keygen.c \
	libotp.h \
	libotp.c \
	paranoia.c

paranoia_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(PURPLE_CFLAGS) \
	-DVERSION=\"$(VERSION)\" \
	-DLIBDIR=\"$(PURPLE_LIBDIR)/purple-2/\" \
	-DDATADIR=\"$(PURPLE_DATADIR)\" \
	-DLOCALEDIR=\"$(PURPLE_DATADIR)/locale\"

BUILT_SOURCES = paranoia_config.h

$(OBJECTS): $(BUILT_SOURCES)

paranoia_config.h: pre_config.h
	$(sedpath) 's/\#define PACKAGE/\#define PARANOIA/g' pre_config.h > $@

EXTRA_DIST = \
	HACKING

DISTCLEANFILES= \
	paranoia_config.h
