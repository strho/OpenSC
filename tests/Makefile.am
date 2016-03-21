MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = test_card.sh yubico_test.sh pkcs15_test.sh

CFLAGS = -std=gnu99 -Wdeprecated-declarations
AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-I$(top_builddir)

AM_LDFLAGS = -no-install

bin_PROGRAMS = pkcs11_tests

check_PROGRAMS = pkcs11_tests
pkcs11_tests_LDADD = -lcmocka
pkcs11_tests_SOURCES = \
    cryptoki.h pkcs11f.h pkcs11.h pkcs11t.h \
    common.c common.h loader.c loader.h \
    test_helpers.c test_helpers.h test_suits.c test_suits.h


dist_check_SCRIPTS = pkcs15_test.sh

dist_check_DATA = \
	resources/cert.der resources/cert.pem resources/message_to_decrypt.dec \
	resources/message_to_encrypt.txt resources/message_to_hash.txt \
	resources/message_to_sign.signature resources/message_to_sign.txt \
	resources/private_key.key resources/private_key.pem \
	resources/public_key.key resources/public_key.pem

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =	\
	LC_ALL="C" \
	EXEEXT=$(EXEEXT) \
	top_builddir="$(top_builddir)" \
	srcdir="$(srcdir)"


# vim: set noexpandtab:
