/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package expiration

import (
	"crypto/x509"
	"encoding/json"
	"github.com/mozilla/CCADB-Tools/capi/lib/certificateUtils"
	"testing"
)

var AmazonRootCA1 = `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----`

var AmazonRootCA1Valid = `-----BEGIN CERTIFICATE-----
MIIFEjCCA/qgAwIBAgITBvHXFfllHZXWP8myqI3v5T1QCDANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xOTAxMjgyMzEzMzlaFw0yMDAy
MjgyMzEzMzlaMIHZMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwC
AQITCERlbGF3YXJlMRwwGgYDVQQPExNQcml2YXRlT3JnYW5pemF0aW9uMRAwDgYD
VQQFEwc1ODQ2NzQzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
MA4GA1UEBxMHU2VhdHRsZTEeMBwGA1UEChMVQW1hem9uIFRydXN0IFNlcnZpY2Vz
MSMwIQYDVQQDExpnb29kLnNjYTFhLmFtYXpvbnRydXN0LmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANvKSz8Hs5lfb80BC6B1ReHEUsAqE4lHy9sd
T6J7TRUkzukhyJmQ+tPS3wD67FSmVeaiSqsqVrJSZocBRtO3KORgAeXjehZ4q2XR
8VxWqU5QS85QT0dWLOf8DiPESHCPjSVEUh58vZ59k2nY2dYjQUz+KYZCci1tE2MU
KlZbtI7YozLkzmaNHkGUDkJqz6KM7YR58Q2+mD/sTg35/lq/0hiXEiNMkdHxZNDt
eM3qUakcu3wxcwC7A3gLfvpWEgnnrIJMQK3iKq6rp81sN0zHHoYkHQ5INRRQ5Kcw
p3HORmXNCLszfvesa2jhrxbGpl5jfVvwD8+if7yTY4YjpwCPHSUCAwEAAaOCAWMw
ggFfMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUVYiPMfFU3kEvv7x7THysxbc4
MPwwHwYDVR0jBBgwFoAUYtRCXoZwdWqQvMa40k1gwjS6UTowHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYh
aHR0cDovL29jc3Auc2NhMWEuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipo
dHRwOi8vY3J0LnNjYTFhLmFtYXpvbnRydXN0LmNvbS9zY2ExYS5jZXIwJQYDVR0R
BB4wHIIaZ29vZC5zY2ExYS5hbWF6b250cnVzdC5jb20wUAYDVR0gBEkwRzANBgtg
hkgBhv1uAQcYAzA2BgVngQwBATAtMCsGCCsGAQUFBwIBFh9odHRwczovL3d3dy5h
bWF6b250cnVzdC5jb20vY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCJZwyxhTd2LKiB
tU1V7MgmOlMT0CzPE4UBRNvwg6FSwhs+l+9PsmRp7NjojK9JrdmKTvMLS8F8N6aX
tp1+kmuipp3j5sLSxN7fsSHL4wXiAcJ1HtUqXZXI3AIUic7DgDCALO/eiwEw8or7
Fd7vBe5KxoOuPbvOnWrvekVWmKBz77i9Tc82NszHmSt2l0cVonVKV/lu72gudm1s
Al7YvDMhiVzz2QrrIaJlN8j5ZvLXzstZ/3qq6Eo/vpweQig4/fdNkp1FBgJ2wvev
C7Y0PtfZJs2mIf9nlVhHIkCKx6uxfIVuh6WCqBznNBItOZdJIna2avmnDt4H6Lw5
i31KU3gP
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
` + AmazonRootCA1

var AmazonRootCA1Expired = `-----BEGIN CERTIFICATE-----
MIIEJjCCAw6gAwIBAgITBn+UamNhIrAVNS+GbA2DjtIeyDANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xNTEyMDMyMjM5MDZaFw0xNTEy
MDYwMDAwMDBaMCgxJjAkBgNVBAMTHWV4cGlyZWQuc2NhMWEuYW1hem9udHJ1c3Qu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv56LNAcn9gwjqR25
Jtw2D9l4T77nXlKCG5AqjDun1qtrifJZBn3YVh9UUOqwtW6BjXGzsCICWIhv92g5
OrzsRsKdwK/Ad35X5CkcGR6tAXJSOL7QosJ7BZnbSPfkqQLqgtttx9N+g+LuAVYb
/TKzJoWhGyJas5N7PufMc1Dy8tCA7TvbCDF6AEYN74rTBSv9iVxfwwT+YUERhZhk
7jUqNkJg5LfyB1aT7zK1xx8UMkeQY/KtAS6YxqjNCvmyPSGZHDE4MujnkCngWSmm
rOg/y1uU9gsX6BteHHyTc0CccO06Pm0qkB5qcoNj2EeF5HdLKXQeJQ4uYD1hmKvg
vYeLsQIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdDgQWBBTHWTL1
sJbjN8v7LJwyNU64kzsc/TAfBgNVHSMEGDAWgBRi1EJehnB1apC8xrjSTWDCNLpR
OjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYIKwYBBQUHAQEEaTBn
MC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYS5hbWF6b250cnVzdC5jb20w
NgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWEuYW1hem9udHJ1c3QuY29tL3Nj
YTFhLmNlcjAoBgNVHREEITAfgh1leHBpcmVkLnNjYTFhLmFtYXpvbnRydXN0LmNv
bTATBgNVHSAEDDAKMAgGBmeBDAECATANBgkqhkiG9w0BAQsFAAOCAQEAiWkrVciR
+Pz5FzVpjeHHqn5XtvS8p0uwSP3C6P8Q8TmPkIiX1hPbN2Xv0h01On+cRyMPjl6a
k/qymZxBX+0JWBBAwnxJHh0v76gIs9IMB95qaDgfq4rdTpItIxh28WKXJyD+KnUg
gYyUorHNOUsbM3Af00BgBf6/xsiCN0DEgKhcfurpK/tCxWj1/Hbcxv7T68ClGtnY
QU+n7nO8Sa1sJJsEOZdAQfVNhJYTVoNxW7QetZ+vWHpSotVpKkr4MKKgIOMOBq9l
/QDfLsmOWFVkjn8m/DkLs+WfCD0sSUbBN4eIVioBcZHucr7BCnJiBjObkwF6IEe2
3cZz3/sPAXlF2g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
` + AmazonRootCA1

// DigiCertGlobalRootCA tacked on as the root
var AmazonRootCA1ValidWithWrongRoot = `-----BEGIN CERTIFICATE-----
MIIFEjCCA/qgAwIBAgITBvHXFfllHZXWP8myqI3v5T1QCDANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xOTAxMjgyMzEzMzlaFw0yMDAy
MjgyMzEzMzlaMIHZMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwC
AQITCERlbGF3YXJlMRwwGgYDVQQPExNQcml2YXRlT3JnYW5pemF0aW9uMRAwDgYD
VQQFEwc1ODQ2NzQzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
MA4GA1UEBxMHU2VhdHRsZTEeMBwGA1UEChMVQW1hem9uIFRydXN0IFNlcnZpY2Vz
MSMwIQYDVQQDExpnb29kLnNjYTFhLmFtYXpvbnRydXN0LmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANvKSz8Hs5lfb80BC6B1ReHEUsAqE4lHy9sd
T6J7TRUkzukhyJmQ+tPS3wD67FSmVeaiSqsqVrJSZocBRtO3KORgAeXjehZ4q2XR
8VxWqU5QS85QT0dWLOf8DiPESHCPjSVEUh58vZ59k2nY2dYjQUz+KYZCci1tE2MU
KlZbtI7YozLkzmaNHkGUDkJqz6KM7YR58Q2+mD/sTg35/lq/0hiXEiNMkdHxZNDt
eM3qUakcu3wxcwC7A3gLfvpWEgnnrIJMQK3iKq6rp81sN0zHHoYkHQ5INRRQ5Kcw
p3HORmXNCLszfvesa2jhrxbGpl5jfVvwD8+if7yTY4YjpwCPHSUCAwEAAaOCAWMw
ggFfMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUVYiPMfFU3kEvv7x7THysxbc4
MPwwHwYDVR0jBBgwFoAUYtRCXoZwdWqQvMa40k1gwjS6UTowHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYh
aHR0cDovL29jc3Auc2NhMWEuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipo
dHRwOi8vY3J0LnNjYTFhLmFtYXpvbnRydXN0LmNvbS9zY2ExYS5jZXIwJQYDVR0R
BB4wHIIaZ29vZC5zY2ExYS5hbWF6b250cnVzdC5jb20wUAYDVR0gBEkwRzANBgtg
hkgBhv1uAQcYAzA2BgVngQwBATAtMCsGCCsGAQUFBwIBFh9odHRwczovL3d3dy5h
bWF6b250cnVzdC5jb20vY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCJZwyxhTd2LKiB
tU1V7MgmOlMT0CzPE4UBRNvwg6FSwhs+l+9PsmRp7NjojK9JrdmKTvMLS8F8N6aX
tp1+kmuipp3j5sLSxN7fsSHL4wXiAcJ1HtUqXZXI3AIUic7DgDCALO/eiwEw8or7
Fd7vBe5KxoOuPbvOnWrvekVWmKBz77i9Tc82NszHmSt2l0cVonVKV/lu72gudm1s
Al7YvDMhiVzz2QrrIaJlN8j5ZvLXzstZ/3qq6Eo/vpweQig4/fdNkp1FBgJ2wvev
C7Y0PtfZJs2mIf9nlVhHIkCKx6uxfIVuh6WCqBznNBItOZdJIna2avmnDt4H6Lw5
i31KU3gP
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----`

// openssl req -x509 -newkey rsa:2048 -keyout priv.pem -sha256 -days 99999 -out fake.pem
// Country Name = US
// Organization Name = Amazon
// CN = Amazon Root CA 1
var FakeAmazonRoot = `-----BEGIN CERTIFICATE-----
MIIC8DCCAdgCCQCbV7pf47q4ozANBgkqhkiG9w0BAQsFADA5MQswCQYDVQQGEwJV
UzEPMA0GA1UECgwGQW1hem9uMRkwFwYDVQQDDBBBbWF6b24gUm9vdCBDQSAxMCAX
DTE5MDIxNjE3MTM1MloYDzIyOTIxMTMwMTcxMzUyWjA5MQswCQYDVQQGEwJVUzEP
MA0GA1UECgwGQW1hem9uMRkwFwYDVQQDDBBBbWF6b24gUm9vdCBDQSAxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/KGykYBGbxZ1/ApdfjSgOf709mH
JzSQpeitWz4AcGBsIk8Z6oSqCMJE+8aZVvzsClItLtC4cxLq7051vAYGgikih1Lz
u9OQfZto6hXW3IolV64EsdXdYcx7NZxR1sLvFI8pvau7fvwVD/+CRc4OqRlIwdFW
Pd18+tsvz+552Y6ZgKRXDSkWovGEs/21u1CZJLBtidpHBUZwA5Mwe56gg8RvYLtd
Bn2PL1qiabdYt3AsheD9/bRHZd0BCJ3tcX3BZsyj85+ZWGr4FCK/A4hjp+VH9R6c
TfcvVA/GYD0BZKvclaJ0e+O3XnfxzeR7V90yRmjmiThvvtkZSUvcK5bwLwIDAQAB
MA0GCSqGSIb3DQEBCwUAA4IBAQBVVJ+Z0rvC5mZqtvAzOiU95TffYwJoOkyLNuRQ
vCEEQaA6dKwB2Uh3PjuVvuJUEAREXK4yp62V5S2jX5MED/+Zwn47QXTczkjYniZv
3Vf0VCoZlp6u76jY88czwmeTzaAfnNU6HXsj0nLhE+WU/Tghpk5hEP0XtMsxRGcu
rTeekWbdI5ZpM4SyWeH/jXcXZAm08Vee3tnRIcOAKCNquCZtTnnbWNoaxfqcQz5x
esqOCKA5wrQK81mjzdyLOZ3ocHqNk0ol1lO5UhNy8G9hwJpq3FepoCtlpuzpsmCS
TmgNcMwcy90GKoD1fwZkig8TaJ76uE1N49T2kCP/KwwtsyQe
-----END CERTIFICATE-----`

var AmazonRootCA1ValidWithFakeRoot = `-----BEGIN CERTIFICATE-----
MIIFEjCCA/qgAwIBAgITBvHXFfllHZXWP8myqI3v5T1QCDANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xOTAxMjgyMzEzMzlaFw0yMDAy
MjgyMzEzMzlaMIHZMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwC
AQITCERlbGF3YXJlMRwwGgYDVQQPExNQcml2YXRlT3JnYW5pemF0aW9uMRAwDgYD
VQQFEwc1ODQ2NzQzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
MA4GA1UEBxMHU2VhdHRsZTEeMBwGA1UEChMVQW1hem9uIFRydXN0IFNlcnZpY2Vz
MSMwIQYDVQQDExpnb29kLnNjYTFhLmFtYXpvbnRydXN0LmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANvKSz8Hs5lfb80BC6B1ReHEUsAqE4lHy9sd
T6J7TRUkzukhyJmQ+tPS3wD67FSmVeaiSqsqVrJSZocBRtO3KORgAeXjehZ4q2XR
8VxWqU5QS85QT0dWLOf8DiPESHCPjSVEUh58vZ59k2nY2dYjQUz+KYZCci1tE2MU
KlZbtI7YozLkzmaNHkGUDkJqz6KM7YR58Q2+mD/sTg35/lq/0hiXEiNMkdHxZNDt
eM3qUakcu3wxcwC7A3gLfvpWEgnnrIJMQK3iKq6rp81sN0zHHoYkHQ5INRRQ5Kcw
p3HORmXNCLszfvesa2jhrxbGpl5jfVvwD8+if7yTY4YjpwCPHSUCAwEAAaOCAWMw
ggFfMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUVYiPMfFU3kEvv7x7THysxbc4
MPwwHwYDVR0jBBgwFoAUYtRCXoZwdWqQvMa40k1gwjS6UTowHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYh
aHR0cDovL29jc3Auc2NhMWEuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipo
dHRwOi8vY3J0LnNjYTFhLmFtYXpvbnRydXN0LmNvbS9zY2ExYS5jZXIwJQYDVR0R
BB4wHIIaZ29vZC5zY2ExYS5hbWF6b250cnVzdC5jb20wUAYDVR0gBEkwRzANBgtg
hkgBhv1uAQcYAzA2BgVngQwBATAtMCsGCCsGAQUFBwIBFh9odHRwczovL3d3dy5h
bWF6b250cnVzdC5jb20vY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCJZwyxhTd2LKiB
tU1V7MgmOlMT0CzPE4UBRNvwg6FSwhs+l+9PsmRp7NjojK9JrdmKTvMLS8F8N6aX
tp1+kmuipp3j5sLSxN7fsSHL4wXiAcJ1HtUqXZXI3AIUic7DgDCALO/eiwEw8or7
Fd7vBe5KxoOuPbvOnWrvekVWmKBz77i9Tc82NszHmSt2l0cVonVKV/lu72gudm1s
Al7YvDMhiVzz2QrrIaJlN8j5ZvLXzstZ/3qq6Eo/vpweQig4/fdNkp1FBgJ2wvev
C7Y0PtfZJs2mIf9nlVhHIkCKx6uxfIVuh6WCqBznNBItOZdJIna2avmnDt4H6Lw5
i31KU3gP
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
` + FakeAmazonRoot

func TestValidChain(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Valid))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := VerifyChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != len(chain) {
		t.Fatalf("wanted %d expiration statues, got %d\n", len(chain), len(statuses))
	}
	for _, status := range statuses {
		if status.Status != Valid {
			t.Fail()
			t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", status)
		}
		s, _ := json.Marshal(status)
		t.Log(string(s))
	}
}

func TestValidMissingRoot(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Valid))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := VerifyChain(chain[:2])
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.Status != IssuerUnknown {
			t.Fail()
			t.Errorf("wanted the leaf to be unexpired, invalid, and with an UNKNOWN issuer, got %v", status)
		}
	}
}

func TestValidMissingIntermediate(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Valid))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := VerifyChain([]*x509.Certificate{chain[0], chain[2]})
	if err != nil {
		t.Fatal(err)
	}
	leaf := statuses[0]
	root := statuses[1]
	if leaf.Status != IssuerUnknown {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, invalid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if root.Status != Valid {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", root)
	}
}

func TestExpiredChain(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Expired))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := VerifyChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != len(chain) {
		t.Fatalf("wanted %d expiration statues, got %d\n", len(chain), len(statuses))
	}
	leaf := statuses[0]
	if leaf.Status != Expired {
		t.Fail()
		t.Errorf("wanted the leaf to be expired, valid, and with a know issuer, got %v", leaf)
	}
	intermediate := statuses[1]
	if intermediate.Status != Valid {
		t.Fail()
		t.Errorf("wanted the intermediate to be unexpired, valid, and with a know issuer, got %v", intermediate)
	}
	root := statuses[2]
	if root.Status != Valid {
		t.Fail()
		t.Errorf("wanted the root to be unexpired, valid, and with a know issuer, got %v", root)
	}
}

func TestExpiredMissingRoot(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Expired))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := VerifyChain(chain[:2])
	if err != nil {
		t.Fatal(err)
	}
	leaf := statuses[0]
	intermediate := statuses[1]
	// certutil only gives one error at time, with expiration having the priority.
	if leaf.Status != Expired {
		t.Fail()
		t.Errorf("wanted the cert to be unexpired, invalid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if intermediate.Status != IssuerUnknown {
		t.Fail()
		t.Errorf("wanted the cert to be unexpired, invalid, and with an UNKNOWN issuer, got %v", intermediate)
	}
}

func TestExpiredMissingIntermediate(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Expired))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := VerifyChain([]*x509.Certificate{chain[0], chain[2]})
	if err != nil {
		t.Fatal(err)
	}
	leaf := statuses[0]
	root := statuses[1]
	// certutil only gives one error at time, with expiration having the priority.
	if leaf.Status != Expired {
		t.Fail()
		t.Errorf("wanted the leaf to be expired, invalid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if root.Status != Valid {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", root)
	}
}

func TestBadIssuer(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1ValidWithWrongRoot))
	if err != nil {
		t.Fatal(err)
	}
	result, _ := VerifyChain(chain)
	leaf := result[0]
	intermediate := result[1]
	root := result[2]
	if leaf.Status != IssuerUnknown {
		t.Errorf("wanted the leaf to be unexpired, valid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if intermediate.Status != IssuerUnknown {
		t.Errorf("wanted the leaf to be unexpired, valid, and with an UNKNOWN issuer, got %v", intermediate)
	}
	if root.Status != Valid {
		t.Errorf("wanted the leaf to be unexpired, valid, and with an known issuer, got %v", root)
	}
}

func TestInvalidSignature(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1ValidWithFakeRoot))
	if err != nil {
		t.Fatal(err)
	}
	result, _ := VerifyChain(chain)
	leaf := result[0]
	intermediate := result[1]
	root := result[2]
	if leaf.Status != IssuerUnknown {
		t.Errorf("wanted the leaf to be unexpired, valid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if intermediate.Status != IssuerUnknown {
		t.Errorf("wanted the leaf to be unexpired, valid, and with an UNKNOWN issuer, got %v", intermediate)
	}
	if root.Status != Valid {
		t.Errorf("wanted the leaf to be unexpired, valid, and with an known issuer, got %v", root)
	}
}
