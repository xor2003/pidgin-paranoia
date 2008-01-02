SUBDIRS = tools

plugindir = $(PURPLE_LIBDIR)/purple-2

plugin_LTLIBRARIES = paranoia.la

paranoia_la_LDFLAGS = -module -avoid-version

paranoia_la_SOURCES = \
	libotp.c \
	libotp.h \
	paranoia.c

paranoia_la_CPPFLAGS = \
	-DVERSION=\"$(VERSION)\" \
	-DLIBDIR=\"$(PURPLE_LIBDIR)/purple-2/\" \
	-DDATADIR=\"$(PURPLE_DATADIR)\" \
	-DLOCALEDIR=\"$(PURPLE_DATADIR)/locale\" \
	$(DEBUG_CFLAGS) \
	$(PURPLE_CFLAGS)

BUILT_SOURCES = paranoia_config.h

$(OBJECTS): $(BUILT_SOURCES)

paranoia_config.h: pre_config.h
	$(sedpath) 's/\#define PACKAGE/\#define PARANOIA/g' pre_config.h > $@

EXTRA_DIST = \
	AUTHORS \
	COPYING \
	ChangeLog \
	INSTALL \
	NEWS \
	README \
	VERSION 

DISTCLEANFILES= \
	paranoia_config.h
