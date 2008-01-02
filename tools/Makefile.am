INCLUDES = $(CFLAGS) $(GLIB_CFLAGS)

# with install: bin_PROGRAMS = otptester
noinst_PROGRAMS = otptester

otptester_SOURCES = \
	otptester.c \
	../libotp.c \
	../libotp.h

otptester_LDADD = $(GLIB_LIBS)
otptester_LDFLAGS = -lm
