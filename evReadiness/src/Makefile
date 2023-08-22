# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CC=clang++
CFLAGS=-Ipkix/include -I/usr/include/nspr4 -I/usr/include/nspr -I/usr/local/include/nspr \
	-I/usr/include/nss3 -I/usr/local/include/nss -I/usr/include/nss \
	-g -Wall -c -std=c++11
LDFLAGS=-lnss3 -lnssutil3 -lnspr4 -lplc4 -lcurl -Wl,-L/usr/local/lib
SOURCES=pkix/lib/pkixbuild.cpp pkix/lib/pkixcert.cpp pkix/lib/pkixcheck.cpp \
	pkix/lib/pkixder.cpp pkix/lib/pkixnames.cpp pkix/lib/pkixnss.cpp \
	pkix/lib/pkixocsp.cpp pkix/lib/pkixresult.cpp pkix/lib/pkixtime.cpp \
	pkix/lib/pkixverify.cpp ev-checker.cpp \
	EVCheckerTrustDomain.cpp Util.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=ev-checker

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

deps-ubuntu:
	sudo apt -y install clang make libcurl4-nss-dev libnspr4-dev libnss3-dev gnutls-bin

deps-rhel:
	sudo dnf install -y clang make nss-devel nspr-devel libcurl-devel gnutls-utils

clean:
	rm -f $(EXECUTABLE) $(OBJECTS) test/*.pem test/*.key test/*.req \
	test/run-tests.sh
