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
#include <string.h>
#include "checks.h"

static const char *error_strings[] =
{
	"E: Error parsing certificate\n", /* ERR_INVALID*/
	"E: Issuer without organizationName\n", /* ERR_ISSUER_ORG_NAME*/
	"E: Issuer without countryName\n", /* ERR_ISSUER_COUNTRY */
	"E: Subject without organizationName, givenName or surname but with streetAddress\n", /* ERR_SUBJECT_ADDR */
	"E: Subject with organizationName, givenName or surname but without stateOrProvince or localityName\n", /* ERR_SUBJECT_ORG_NO_PLACE */
	"E: Subject without organizationName, givenName or surname but with stateOrProvince or localityName\n", /* ERR_SUBJECT_NO_ORG_PLACE */
	"E: Fails decoding the characterset\n", /*ERR_INVALID_ENCODING */
	"E: Contains a null character in the string\n", /* ERR_STRING_WITH_NUL */
	"E: Name entry contains an invalid type\n", /* ERR_INVALID_NAME_ENTRY_TYPE */
	"E: The string contains non-printable control characters\n", /* ERR_NON_PRINTABLE */
	"E: Subject with organizationName, givenName or surname but without countryName\n", /* ERR_SUBJECT_COUNTRY */
	"E: Domain validated certificate with organizationName\n", /* ERR_DOMAIN_WITH_ORG */
	"E: Organization validated certificate but without organizationName\n", /* ERR_ORGANIZATION_WITHOUT_ORG */
	"E: No policy extension\n", /* ERR_NO_POLICY */
	"E: No Subject alternative name extension\n", /* ERR_NO_SUBJECT_ALT_NAME */
	"E: Certificate not version 3\n", /* ERR_NOT_VERSION3 */
	"E: Error parsing URL\n", /* ERR_INVALID_URL */
	"E: The certificate is valid for longer than 60 months\n", /* ERR_LONGER_60_MONTHS */
	"E: countryName not 2 characters long\n", /* ERR_COUNTRY_SIZE */
	"E: Invalid time format\n", /* ERR_INVALID_TIME_FORMAT */
	"E: Duplicate extension\n", /* ERR_DUPLICATE_EXTENSION */
	"E: Invalid CRL distribution point\n", /* ERR_INVALID_CRL_DIST_POINT */
	"E: Invalid display text type\n", /* ERR_INVALID_DISPLAY_TEXT_TYPE */
	"E: Invalid display text length\n", /* ERR_INVALID_DISPLAY_TEXT_LENGTH */
	"E: Invalid user notice type\n", /* ERR_INVALID_TYPE_USER_NOTICE */
	"E: Invalid policy qualifier id\n", /* ERR_INVALID_POLICY_QUALIFIER_ID */
	"E: Individual without name\n", /* ERR_INDIVIDUAL_WITHOUT_NAME */
	"E: Individual without country\n", /* ERR_INDIVIDUAL_WITHOUT_COUNTRY */
	"E: EV certificate without organization\n", /* ERR_EV_WITHOUT_ORGANIZATION */
	"E: EV certificate without business\n", /* ERR_EV_WITHOUT_BUSINESS */
	"E: EV certificate without jurisdiction country\n", /* ERR_EV_WITHOUT_JURISDICTION_COUNTRY */
	"E: EV certificate without number\n", /* ERR_EV_WITHOUT_NUMBER */
	"E: Domain validated certificate but with streetAddress\n", /* ERR_DOMAIN_WITH_STREET */
	"E: Domain validated certificate but with localityName\n", /* ERR_DOMAIN_WITH_LOCALITY */
	"E: Domain validated certificate but with stateOrProvinceName\n", /* ERR_DOMAIN_WITH_STATE */
	"E: Domain validated certificate but with postalCode\n", /* ERR_DOMAIN_WITH_POSTAL */
	"E: Organization validated certificate but without country\n", /* ERR_ORGANIZATION_WITHOUT_COUNTRY */
	"E: commonName too long\n", /* ERR_COMMON_NAME_SIZE */
	"E: localityName too long\n", /* ERR_LOCALITY_NAME_SIZE */
	"E: stateOrProvinceName too long\n", /* ERR_STATE_NAME_SIZE */
	"E: organizationName too long\n", /* ERR_ORGANIZATION_NAME_SIZE */
	"E: organizationalUnitName too long\n", /* ERR_ORGANIZATIONAL_UNIT_NAME_SIZE */
	"E: serialNumber too long\n", /* ERR_SERIAL_NUMBER_SIZE */
	"E: postalCode too long\n", /* ERR_POSTAL_CODE_SIZE */
	"E: emailAddress too long\n", /* ERR_EMAIL_SIZE */
	"E: givenName too long\n", /* ERR_GIVEN_NAME_SIZE */
	"E: surname too long\n", /* ERR_SURNAME_SIZE */
	"E: streetAddress too long\n", /* ERR_STREET_ADDRESS_SIZE */
	"E: authorityInformationAccess is marked critical\n", /* ERR_AIA_CRITICAL */
	"E: No OCSP over HTTP\n",  /* ERR_NO_OCSP_HTTP */
	"E: no authorityInformationAccess extension\n", /* ERR_NO_AIA */
	"E: Invalid type in SAN entry\n", /* ERR_SAN_TYPE */
	"E: Invalid type in GeneralName\n", /* ERR_GEN_NAME_TYPE */
	"E: EV certificate valid longer than 27 months\n", /* ERR_EV_LONGER_27_MONTHS */
	"E: subjectAltName without name\n", /* ERR_SAN_WITHOUT_NAME */
	"E: Invalid length of IP address\n", /* ERR_IP_FAMILY */
	"E: commonName not in subjectAltName extension\n", /* ERR_CN_NOT_IN_SAN */
	"E: Invalid length of businessCategory\n", /* ERR_BUSINESS_CATEGORY_SIZE */
	"E: Invalid length of dnQualifier\n", /* ERR_DN_QUALIFIER_SIZE */
	"E: URL contains a null character\n", /* ERR_URL_WITH_NUL */
	"E: postOfficeBox too long\n", /* ERR_POST_OFFICE_BOX_SIZE */
	"E: IP address in dns name\n", /* ERR_IP_IN_DNSNAME */
	"E: Serial number not positive\n", /* ERR_SERIAL_NOT_POSITIVE */
	"E: Serial number too large\n", /* ERR_SERIAL_TOO_LARGE */
	"E: ASN1 integer not minimally encoded\n", /* ERR_ASN1_INTEGER_NOT_MINIMAL */
	"E: RSA modulus smaller than 2048 bit\n", /* ERR_RSA_SIZE_2048 */
	"E: RSA public exponent not odd\n", /* ERR_RSA_EXP_NOT_ODD */
	"E: RSA public exponent not equal to 3 or more\n", /* ERR_RSA_EXP_3 */
	"E: RSA modulus has small factor\n", /* ERR_RSA_SMALL_FACTOR */
	"E: EC point at infinity\n", /* ERR_EC_AT_INFINITY */
	"E: EC point not on curve\n", /* ERR_EC_POINT_NOT_ON_CURVE */
	"E: EC key has invalid group order\n", /* ERR_EC_INVALID_GROUP_ORDER */
	"E: EC key has incorrect group order\n", /* ERR_EC_INCORRECT_ORDER */
	"E: EC curve is not one of the allowed curves\n", /* ERR_EC_NON_ALLOWED_CURVE */
	"E: Unknown public key type\n", /* ERR_UNKNOWN_PUBLIC_KEY_TYPE */
	"E: Subject without organizationName, givenName or surname but with postalCode\n", /* ERR_SUBJECT_POSTAL */
	"E: Domain validated certificate but with givenName or surname\n", /* ERR_DOMAIN_WITH_NAME */
	"E: Subject with givenName or surname but without the CAB IV policy oid\n", /* ERR_NAME_NO_IV_POLICY */
	"E: CA root certificate with Extended Key Usage\n", /* ERR_ROOT_CA_WITH_EKU */
	"E: Extended Key Usage without any entries\n", /* ERR_EMPTY_EKU */
	"E: Extended Key Usage lacks a required purpose\n", /* ERR_MISSING_EKU */
	"E: Invalid length of domainComponent\n", /* ERR_DOMAINCOMPONENT_SIZE */
	"E: Invalid length of unstructuredName\n", /* ERR_UNSTRUCTUREDNAME_SIZE */
	"E: Teletex string with an escape sequence\n", /* ERR_TELETEX_WITH_ESCAPE */
	"E: Baseline Requirements policy present for non server authentication certificate\n", /* ERR_POLICY_BR */
};

static const char *warning_strings[] = {
	"W: The name entry contains something that is not a PrintableString or UTF8String\n", /* WARN_NON_PRINTABLE_STRING */
	"W: The certificate is valid for longer than 39 months\n", /* WARN_LONGER_39_MONTHS */
	"W: CA certificate checked as if it was a subscriber certificate\n", /* WARN_CHECKED_AS_SUBSCRIBER */
	"W: Subscriber certificate checked as if it was a CA certificate\n", /* WARN_CHECKED_AS_CA */
	"W: CRL distribution point uses relative name\n", /* WARN_CRL_RELATIVE */
	"W: No HTTP URL for issuing certificate\n", /* WARN_NO_ISSUING_CERT_HTTP */
	"W: Duplicate SAN entry\n", /* WARN_DUPLICATE_SAN */
	"W: EV certificate valid longer than 12 months\n", /* WARN_EV_LONGER_12_MONTHS */
	"W: Unknown extended key usage\n", /* WARN_UNKNOWN_EKU */
	"W: RSA public exponent not in range of 2^16+1 to 2^256-1\n", /* WARN_RSA_EXP_RANGE */
	"W: Policy information has qualifier other than CPS URI\n", /* WARN_POLICY_QUALIFIER_NOT_CPS */
	"W: explicitText is not using a UTF8String\n", /* WARN_EXPLICIT_TEXT_ENCODING */
	"W: Subscriber certificate without Extended Key Usage\n", /* WARN_NO_EKU */
	"W: No commonName\n", /* WARN_NO_CN */
	"W: TLS client with DNS or IP address\n", /* WARN_TLS_CLIENT_DNS */
};

static const char *info_strings[] = {
	"I: Subject has a deprecated CommonName\n", /* INF_SUBJECT_CN */
	"I: String not checked\n", /* INF_STRING_NOT_CHECKED */
	"I: CRL is not a URL\n", /* INF_CRL_NOT_URL */
	"I: Unknown validation policy\n", /* INF_UNKNOWN_VALIDATION */
	"I: Name entry length not checked\n", /* INF_NAME_ENTRY_LENGTH_NOT_CHECKED */
};

/* 
 * Turn the error information into strings.
 * Returns a buffer that should be free()d
 */
char *get_messages()
{
	char *buffer;

	/* Should be large enough for all strings. */
	buffer = malloc(16384);
	buffer[0] = '\0';

	for (int i = 0; i <= MAX_ERR; i++)
	{
		if (GetBit(errors, i))
		{
			strcat(buffer, error_strings[i]);
		}
	}

	for (int i = 0; i <= MAX_WARN; i++)
	{
		if (GetBit(warnings, i))
		{
			strcat(buffer, warning_strings[i]);
		}
	}

	for (int i = 0; i <= MAX_INF; i++)
	{
		if (GetBit(info, i))
		{
			strcat(buffer, info_strings[i]);
		}
	}

	return buffer;
}

