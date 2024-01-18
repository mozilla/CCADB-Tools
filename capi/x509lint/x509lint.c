/*
 * Copyright (c) 2016 Kurt Roeckx <kurt@roeckx.be>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "checks.h"
#include "messages.h"

static const char *usage = "Usage: x509lint file [subscriber|intermediate|ca](default subscriber)\n";

static int LoadCert(const char *filename, unsigned char **buffer, size_t *buflen)
{
	long size;
	FILE *f;

	f = fopen(filename, "rb");
	if (f == NULL)
	{
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0)
	{
		return -1;
	}
	size = ftell(f);
	if (size == -1)
	{
		return -1;
	}
	*buffer = malloc(size);
	if (fseek(f, 0, SEEK_SET) != 0)
	{
		free(*buffer);
		*buffer = NULL;
		return -1;
	}
	if (fread(*buffer, 1, size, f) != size)
	{
		free(*buffer);
		*buffer = NULL;
		return -1;
	}
	fclose(f);

	*buflen = size;

	return 0;
}

static CertType GetType(int argc, char *argv[]) {
	if (argc < 3) 
	{
		// By default, if no argument is given for
		// cert type then default to a subscriber type.
		return SubscriberCertificate;
	}
	char *type = argv[2];
	if (strcmp(type, "subscriber") == 0) 
	{
		return SubscriberCertificate;
	} 
	else if (strcmp(type, "intermediate") == 0) 
	{
		return IntermediateCA;
	} 
	else if (strcmp(type, "ca") == 0) 
	{
		return RootCA;
	} 
	else 
	{
		printf("%s is not a valid certificate type\n", type);
		printf(usage);
		exit(1);
	}
}


int main(int argc, char *argv[])
{
	unsigned char *buffer;
	size_t buflen;

	if (argc != 2 && argc != 3)
	{
		printf(usage);
		exit(1);
	}

	CertType type = GetType(argc, argv);

	if (LoadCert(argv[1], &buffer, &buflen) != 0)
	{
		fprintf(stderr, "Unable to read certificate\n");
		exit(1);
	}

	check_init();
	
	check(buffer, buflen, PEM, type);

	char *m = get_messages();
	printf("%s", m);
	free(m);

	free(buffer);

	check_finish();

	return 0;
}

