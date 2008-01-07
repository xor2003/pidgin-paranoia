INCLUDES = $(GLIB_CFLAGS)
INCLUDES += $(GTHREAD_CFLAGS)
INCLUDES += $(GOBJECT_CFLAGS)

# with install: bin_PROGRAMS = otptester
noinst_PROGRAMS = otptester

otptester_SOURCES = \
	otptester.c \
	../keygen.c \
	../keygen.h \
	../libotp.c \
	../libotp.h

otptester_LDADD = $(GLIB_LIBS)
otptester_LDADD += $(GTHREAD_LIBS)
otptester_LDADD += $(GOBJECT_LIBS)

otptester_LDFLAGS = -lm
