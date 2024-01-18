#ifndef _ASN1_TIME_H_
#define _ASN1_TIME_H_

#include <stdbool.h>
#include <time.h>
#include <openssl/asn1.h>

/*
 * Converts an ASN1_TIME to a struct tm.  Only the fields tm_year, tm_mon,
 * tm_mday, tm_hour, tm_min and tm_sec are filled in, the rest are set to 0.
 *
 * The values are stored in UTC, and so are not usable for a function
 * like mktime().
 *
 * It does not support the full ASN1 syntax, just those needed for X509
 *
 * Returns true on success and false on failure.
 */
bool asn1_time_to_tm(ASN1_TIME *time, struct tm *tm);

#endif

