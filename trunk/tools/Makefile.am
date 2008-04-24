
# with install: bin_PROGRAMS = ...
noinst_PROGRAMS = \
	otptester \
	otp	

# ---- otptester ----

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

# ---- otp cli tool ----

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
