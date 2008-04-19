
# with install: bin_PROGRAMS = otptester
noinst_PROGRAMS = otptester

otptester_SOURCES = \
	otptester.c

nodist_otptester_SOURCES = \
	../otperror.h \
	../keygen.c \
	../keygen.h \
	../libotp.c \
	../libotp.h
	../libotp-internal.h

otptester_CPPFLAGS = $(GLIB_CFLAGS)

otptester_LDADD = $(GLIB_LIBS)

# with install: bin_PROGRAMS = otp
noinst_PROGRAMS = otp

otp_SOURCES = \
	otp.c

nodist_otp_SOURCES = \
	../key_management.h \
	../key_management.c \
	../otperror.h \
	../keygen.c \
	../keygen.h \
	../libotp.c \
	../libotp.h
	../libotp-internal.h

otp_CPPFLAGS = $(GLIB_CFLAGS)

otp_LDADD = $(GLIB_LIBS)
