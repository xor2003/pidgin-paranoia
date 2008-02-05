
# with install: bin_PROGRAMS = otptester
noinst_PROGRAMS = otptester

otptester_SOURCES = \
	otptester.c

nodist_otptester_SOURCES = \
	../keygen.c \
	../keygen.h \
	../libotp.c \
	../libotp.h

otptester_CPPFLAGS = $(GLIB_CFLAGS)

otptester_LDADD = $(GLIB_LIBS)
