# $Id: Makefile,v 1.1.1.1 2007/01/11 15:53:57 dhartmei Exp $
#
# Copyright (c) 2026 Vittorio Moccia / ITB.it
# Licensed under the PolyForm Noncommercial License 1.0.0.
# https://polyformproject.org/licenses/noncommercial/1.0.0/

CC = gcc
INSTALL = install -c
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
DATADIR = /var/share/DarkSpam
CFLAGS = -O2 -D_REENTRANT  -Wall -g

# Linux
LDFLAGS = -lmilter -lpthread -ldb-5.3

PROG=	DarkSpam
SRCS=	DarkSpam.c
MAN=	

# CFLAGS+=	-I/usr/src/gnu/usr.sbin/sendmail/include

all: DarkSpam

DarkSpam: DarkSpam.o DB.o Parse.o
	$(CC) -o DarkSpam DarkSpam.o DB.o Parse.o $(LDFLAGS)
#	strip DarkSpam

DarkSpam.o: DarkSpam.c DarkSpam.h
	$(CC) $(CFLAGS) -c DarkSpam.c

DB.o: DB.c DarkSpam.h
	$(CC) $(CFLAGS) -c DB.c

Parse.o: Parse.c DarkSpam.h
	$(CC) $(CFLAGS) -c Parse.c


clean:
	rm -f DarkSpam.o
	rm -f Parse.o
	rm -f DB.o
	rm -f DarkSpam

