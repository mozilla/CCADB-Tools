# CCADB Intermediate Cert Add/Update API

## **Context**

DigiCert has collaberated with Mozilla to develop an API that will allow CAs to automate the upload of new intermediate certificates to the Common CA Database (CCADB). CCADB is built on the SalesForce platform and so the API leverages both built-in SalesForce features, combinedwith custom API endpoints created by Mozilla.

---

## **API Authentication**

Authentication is handled through SalesForce standard Oauth 2. 

For a CA to use this API, they will need to ask Mozilla to do the following:
1. Create a new Community User to be used by the CA for API transactions.
2. Configure a SalesForce Connected App for the API. The connected app will have a unique `Consumer Key` and `Consumer Secret` that must be included in the authentication request.

An authentication request is made to the SalesForce Instance URL of the CCADB:

`POST https://[SALESFORCE_INSTANCE_URL]/services/oauth2/token`


### **Retrieving the Refresh Token**

Authenticating using a **Community User** through the SalesForce standard API requires going through an OAuth process *in the browser* and retrieving the value of the `code` variable in the GET variables in the browser addresss bar.

1. In the browser go to the following URL (replacing `[SALESFORCE_INSTANCE_URL]` with the URL of the SalesForce instance to which you are authenticating) and the `[CLIENT_ID]` with the Consumer Key recieved from Mozilla.

   `https://[SALESFORCE_INSTANCE_URL]/services/oauth2/authorize?client_id=[CLIENT_ID]&redirect_uri=[SALESFORCE_INSTANCE_URL]&response_type=code`

2. When the page displays the standard SalesForce login form, sign in using the credentials of the **Community User**

3. After you submit the login form you will be redirected to a page to approve the OAuth permission grants. Look in the browser address bar to find the `code` GET variable, and copy the value of `code` and save it for the next step. 

4. Using POSTman or another tool for making REST API calls, make a single POST request to `POST https://[SALESFORCE_INSTANCE_URL]/services/oauth2/token` with the following POST variables:

    * `client_id` 
   
        The client_id shoud contain the `Consumer Key` recieved from Mozilla.

    * `client_secret`
   
        The client_secret should contain the `Consumer Secret` received from Mozilla.

    * `grant_type`

        To authenticate with the community user, grant_type should be `code`.

    * `redirect_url`

        The redirect_url should contain the same `[SALESFORCE_INSTANCE_URL]` that you have been using

    * `code`

        The code should contain the code value you copied from the URL in the browser. *This code can only be used once, so don't submit it multiple times or you will have to start the process over again in the browser.*

5. If your authentication POST request was successful, you will recieve JSON response that looks like this:

    ```
    {
        "access_token": "Ml84H6sBl3dzuZzb2cWahEFaOX4Fh0CwRGN2KHaaaGZdseh6gyY48rmqziSuORyYXxVl7e5ce8S8i0gS3OcApdyVPZryQSd6B8Eus9GuLvFckyNTnzuakeIK",
        "refresh_token": "2x8rydHsbZSMfzVnVtQVjecOYyKkAA9F3KViWYAGhZ8Yat9XdNqJo6rQJtL5ycLtoLYafPNAmED2LdYZj9YqsTl",
        "sfdc_community_url": "https://[SALESFORCE_INSTANCE_URL]",
        "sfdc_community_id": "WK600000000LQaMNCE",
        "signature": "luWlAyVWdiJm39QCbxAR3FOkQwpRK3ri5xVaVqRS",
        "scope": "visualforce refresh_token web api full",
        "id_token": "EasHJy4Tszdl5vR3S0sJR6pz0iA5m2YsWSUSIyvdrGv8iWJ6dObqg"
        "issued_at": "1507125410916"
    }
    ```

6. Copy the value of the `refresh_token`. You will need to store it for subsequent authentication requests.


### **Refresh Token Authenticaton & Bearer Token**

Once you have the `refresh_token` it can be reused for subsequent API authentication requests. Whenever API operations are needed you will first need to send an authentication request to retrieve a temporary bearer token that will need to be included in every API request.

To authenticate and retrieve a new bearer token send a POST request to the same authentication endpoint `POST https://[SALESFORCE_INSTANCE_URL]/services/oauth2/token` with the following POST variables:

* `client_id` 

    The client_id shoud contain the `Consumer Key` recieved from Mozilla.

* `client_secret`

    The client_secret should contain the `Consumer Secret` received from Mozilla.

* `grant_type`

    To authenticate with the community user using the refresh_token we retrieved, grant_type should be `refresh_token`.

* `refresh_token`

    The refresh_token should contain the value of the refresh_token we retrieved above

If your authentication POST request was successful, you will recieve JSON response that looks like this:

```
{
    "access_token": "00D0m0000008ikw!ARgSQKvU..3KO0fNwt_vNdkrMCvgmASPpK8EEQDtBCc2zNVYtnRW7vkMbDcz37LZgNw0PplxdiFrxRWS4vRFqw8tLS_tTRaD",
    "sfdc_community_url": "https://[SALESFORCE_INSTANCE_URL]",
    "sfdc_community_id": "WK600000000LPjAGDC",
    "signature": "aHwST5cMLB63XBSmalnay9QR0TLt7Mc/DGB9kT1MuFc=",
    "scope": "refresh_token visualforce web api full",
    "instance_url": "[SALESFORCE_INSTANCE_URL]",
    "id": "https://[SALESFORCE_INSTANCE_URL]/id/00D0r0000009ixwOAA/0040r000002m8yZAAY",
    "token_type": "Bearer",
    "issued_at": "1608173806332"
}
```

All subsequent requests to the API should include the access token in the Authorization Header:

`Authorizaton Bearer 00D0m0000008ikw!ARgSQKvU..3KO0fNwt_vNdkrMCvgmASPpK8EEQDtBCc2zNVYtnRW7vkMbDcz37LZgNw0PplxdiFrxRWS4vRFqw8tLS_tTRaD`

---

## **CCADB API: Upload New Intermediate Certificate**

To upload a new intermediate certificate into CCADB, you must send both the PEM and its parent PEM. The CCADB API will parse the PEM and populate the CCADB record.

### **Request**

`POST https://[SALESFORCE_INSTANCE_URL]/services/apexrest/create/intermediatecert`

```
{
    "CertificateInformation": {
        "SalesforceRecordId": "",
        "CAOwner": "Digicert",
        "SubordinateCAOwner": "Digicert",
        "IntermediateCertificateName": "Test Intermediate Cert",
        "IntermediateCertPEM": "-----BEGIN CERTIFICATE-----MIIHVDCCBjygAwIBAgIRYUlF+VXF2FWFqCo472HfZlwwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQR2xvYmFsU2lnbiNudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4XDTE0MDUyODAwMDAwMFoXDTE5MDUyODAwMDAwMFoweDELMAkGA1UEBhMCREUxDzANBgNVBAcTBk11bmljaDEeMBwGA1UEChMVR2llc2Vja2UgYW5kIERldnJpZW50MRUwEwYDVQQLQwxDb3Jwb3JhdGUgQ0ExITAfBgMVBAMTGEdpZXNlY2tlIGFuZCBEZXZyaWVudCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANWu5Jjc3fah78pqjmfQwOiEti0wkb/YyoBxahiMcyLmNybDCBhAYIKwYBBQUHAQEEeDB2MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vdHJ1c3Ryb290ZzIwPwYIKwYBBQUHMAKGM2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3RydXN0cm9vdGcyLmNydDAdBgNVHQ4EFgQU5mi9zkOA6ddzO7ndeSfw23lzoMYwHwYDVR0jBBgwFoAUFPblizG2RYBKTG38woeJyjbDkGIwDQYJKoZIhvcNAQEFBQADggEBAJATbmLh0flTPZPqd36upxjQcrpDTu6jeMXc1nGruOSmuGnANeyVC6PXU48HKB/BJLvNtyP/1Yzuqe3Y01oEgAYyrYpYBGH4I24gezvgtFF+6J90Ul7cKfup4p0jb2A6jtPSqT5Cu0N2HnONf1VuzL7UTGjJn4Rv6LtIVN3vga0VitKd1jv1RRliRGrY0QJHhL0DwSL1Zjt+Nh/Hm7NoWdKtLzrgzqY4hCvuSEjIa7XWDtTOT6suxvVyZP4l3eURH4eg0kWOJVh97PkwK1S307u/0yx94jirzMnKBfhv/uEXSkPJUu6LwNuWrseosrl9VdGooFT7g/Wf99gsu3iJTf0=-----END CERTIFICATE-----",
        "ParentCertPEM": "-----BEGIN CERTIFICATE-----MIIEvTCCA6WgAwIBAgIBADANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJFVTEnMCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzNjg3MSMwIQYDVQQLExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9vdDAeFw0wMzA5MzAzNjEzNDNaFw0zNzA5MzAxNjEzNDRaMH8xCzAJBgNVBAYTAkVVMScwJQYDVQQKEx5BQyBDYW1lcmZpcm1hIFNBIENJRiBBODI3NDMyODcxIzAhBqNVBAsTGmh0dHA6Ly93d3cuY2jjbWJlcnNpZ24ub3JnMSIwIAYDVQQDExlDaGFtYmVycyBvZiBDb21tZXJjZSBSb290MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAtzZV1iZXJzcm9vdEBjaGFtYmVyc2lnbi5vcmcwWAYDVR0gBFEwTzBNBgsrBgEEAYGHLgoDATA+MDwGCCsGAQUFBwIBFjBodHRwOi8vY3BzLmNoYW1iZXJzaWduLm9yZy9jcHMvY2hhbWJlcnNyb290Lmh0bWwwDQYJKoZIhvcNAQEFBQADggEBAAxBl8IahsAifJ/7kPMa0QOx7xP5IV8EnNrJpY0nbJaHkb5BkAFyk+cefV/2icZdp0APJaxJRUXcLo0waLIJuvvDL8y6C98/d3tGfToSJI6WjzwFCm/SlCgdbQzALogi1djPHRPH8EjX1wWnz8dHnjs8NMiAT9QUu/wNUPf6s+xCX6ndbcj0dc97wXImsQEcXCz9ek60AcUFV7nnPKoF2YjpB0ZBzu9Bga5Y34OirsrXdx/nADydb47kMgkdTXg0eDQ8lJsm7U9xxhl6vSAiSFr+S30Dt+dYvsYyTnQeaN2oaFuzPu5ifdmA6Ap1erfutGWaIZDgqtCYvDi1czyL+Nw=-----END CERTIFICATE-----",
        "ConsentforTechnicallyConstrainedCert": true
    },
    "RevocationInformation": {
        "RevocationStatus": "",
        "DateOfRevocation": null,
        "RevocationReasonCode": "",
        "AlternateCRL": ""
    },
    "OtherCAInformation": {
        "RecognizedCAADomains": "",
        "ProblemReportingMechanism": ""
    },
    "AuditorInformation": {
        "Auditor": "Auditor Name",
        "AuditorLocation": "United States"
    },
    "AuditInformation": {
        "AuditSameAsParent": false,
        "StandardAudit": "http://URL/audit04FINAL.PDF",
        "StandardAuditType": "ETSI EN 319 411",
        "StandardAuditStatementDate": "2018-10-10",
        "StandardAuditPeriodStartDate": "2018-10-10",
        "StandardAuditPeriodEndDate": "2018-10-10",
        "CodeSigningAudit": "",
        "CodeSigningAuditType": "",
        "CodeSigningAuditStatementDate": "",
        "CodeSigningAuditPeriodStartDate": "",
        "CodeSigningAuditPeriodEndDate": "",
        "BRAudit": "",
        "BRAuditType": "",
        "BRAuditStatementDate": "",
        "BRAuditPeriodStartDate": "",
        "BRAuditPeriodEndDate": "",
        "EVSSLAudit": "",
        "EVSSLAuditType": "",
        "EVSSLAuditStatementDate": "",
        "EVSSLAuditPeriodStartDate": "",
        "EVSSLAuditPeriodEndDate": "",
        "EVCodeSigningAudit": "",
        "EVCodeSigningAuditType": "",
        "EVCodeSigningAuditStatementDate": "",
        "EVCodeSigningAuditPeriodStartDate": "",
        "EVCodeSigningAuditPeriodEndDate": ""
    },
    "PolicyInformation": {
        "CPCPSSameAsParent": false,
        "PolicyDocumentation": "",
        "DocumentRepositatory": "https://URL/repository/CA#CPS",
        "CertificatePolicy": "",
        "CertificationPracticeStatement": "https://URL/cps.pdf",
        "CPCPSLastUpdatedDate": "2019-02-01"
    },
    "Description": "",
    "PublicComments": ""
}
```

### **Success Response**
If the upload request was successful you will receive a HTTP Status Code of `200` with JSON in the body containing the *unique salesforced ID* of the CCADB record that was created:

```
{
    "ProcessingStatus": "Success",
    "Errors/Warnings": [],
    "SalesforceRecordId": "0010r00000damffAAA"
}
```

### **Fail Response**
If the upload request failed you will receive a HTTP Status Code of `400` with JSON in the body containing information about the failure. If the upload failed because the a record for the PEM already exists, the salesforce record ID of the existing record will also be returned.
```
{
    "ProcessingStatus": "Fail",
    "Errors/Warnings": [
        "This Intermediate Certificate already exists in CCADB."
    ],
    "SalesforceRecordId": "0010r00000damffAAA"
}
```

---

## **CCADB API: Update Existing Intermediate Certificate**

To update an existing record in the CCADB, you POST to the exact same endpoint as you did to upload a cert, except that the request includes the unique salesforce id for the record that you are updating in the `SalesforceRecordId` field. At a minimum you have to supply the `SalesforceRecordId` and the `IntermediateCertPEM`

`POST https://[SALESFORCE_INSTANCE_URL]/services/apexrest/create/intermediatecert`

```
{
    "CertificateInformation": {
        "SalesforceRecordId": "0010r00000damffAAA",
        "CAOwner": "Digicert",
        "SubordinateCAOwner": "Digicert",
        "IntermediateCertificateName": "Test Intermediate Cert",
        "IntermediateCertPEM": "-----BEGIN CERTIFICATE-----MIIHVDCCBjygAwIBAgIRYUlF+VXF2FWFqCo472HfZlwwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQR2xvYmFsU2lnbiNudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4XDTE0MDUyODAwMDAwMFoXDTE5MDUyODAwMDAwMFoweDELMAkGA1UEBhMCREUxDzANBgNVBAcTBk11bmljaDEeMBwGA1UEChMVR2llc2Vja2UgYW5kIERldnJpZW50MRUwEwYDVQQLQwxDb3Jwb3JhdGUgQ0ExITAfBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMBIGA1UdEwEB/wQIMAYBAf8CAQAwgd8GA1UdHgSB1zCB1KCB0TALgglnaS1kZS5ZzIwPwYIKwYBBQUHMAKGM2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3RydXN0cm9vdGcyLmNydDAdBgNVHQ4EFgQU5mi9zkOA6ddzO7ndeSfw23lzoMYwHwYDVR0jBBgwFoAUFPblizG2RYBKTG38woeJyjbDkGIwDQYJKoZIhvcNAQEFBQADggEBAJATbmLh0flTPZPqd36upxjQcrpDTu6jeMXc1nGruOSmuGnANeyVC6PXU48HKB/BJLvNtyP/1Yzuqe3Y01oEgAYyrYpYBGH4I24gezvgtFF+6J90Ul7cKfup4p0jb2A6jtPSqT5Cu0N2HnONf1VuzL7UTGjJn4Rv6LtIVN3vga0VitKd1jv1RRliRGrY0QJHhL0DwSL1Zjt+Nh/Hm7NoWdKtLzrgzqY4hCvuSEjIa7XWDtTOT6suxvVyZP4l3eURH4eg0kWOJVh97PkwK1S307u/0yx94jirzMnKBfhv/uEXSkPJUu6LwNuWrseosrl9VdGooFT7g/Wf99gsu3iJTf0=-----END CERTIFICATE-----",
        "ParentCertPEM": "-----BEGIN CERTIFICATE-----MIIEvTCCA6WgAwIBAgIBADANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJFVTEnMCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzNjg3MSMwIQYDVQQLExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9vdDAeFw0wMzA5MzAzNjEzNDNaFw0zNzA5MzAxNjEzNDRaMH8xCzAJBgNVBAYTAkVVMScwJQYDVQQKEx5BQyBDYW1lcmZpcm1hIFNBIENJRiBBODI3NDMyODcxIzAhBqNVBAsTGmh0dHA6Ly93d3cuY2jjbWJlcnNpZ24ub3JnMSIwIAYDVQQDExlDaGFtYmVycyBvZiBDb21tZXJjZSBSb290MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAtzZVoYW1iZXJzcm9vdEBjaGFtYmVyc2lnbi5vcmcwWAYDVR0gBFEwTzBNBgsrBgEEAYGHLgoDATA+MDwGCCsGAQUFBwIBFjBodHRwOi8vY3BzLmNoYW1iZXJzaWduLm9yZy9jcHMvY2hhbWJlcnNyb290Lmh0bWwwDQYJKoZIhvcNAQEFBQADggEBAAxBl8IahsAifJ/7kPMa0QOx7xP5IV8EnNrJpY0nbJaHkb5BkAFyk+cefV/2icZdp0APJaxJRUXcLo0waLIJuvvDL8y6C98/d3tGfToSJI6WjzwFCm/SlCgdbQzALogi1djPHRPH8EjX1wWnz8dHnjs8NMiAT9QUu/wNUPf6s+xCX6ndbcj0dc97wXImsQEcXCz9ek60AcUFV7nnPKoF2YjpB0ZBzu9Bga5Y34OirsrXdx/nADydb47kMgkdTXg0eDQ8lJsm7U9xxhl6vSAiSFr+S30Dt+dYvsYyTnQeaN2oaFuzPu5ifdmA6Ap1erfutGWaIZDgqtCYvDi1czyL+Nw=-----END CERTIFICATE-----",
        "ConsentforTechnicallyConstrainedCert": true
    },
    "RevocationInformation": {
        "RevocationStatus": "",
        "DateOfRevocation": null,
        "RevocationReasonCode": "",
        "AlternateCRL": ""
    },
    "OtherCAInformation": {
        "RecognizedCAADomains": "",
        "ProblemReportingMechanism": ""
    },
    "AuditorInformation": {
        "Auditor": "Auditor Name",
        "AuditorLocation": "United States"
    },
    "AuditInformation": {
        "AuditSameAsParent": false,
        "StandardAudit": "https://URL/auditFINAL.PDF",
        "StandardAuditType": "ETSI EN 319 411",
        "StandardAuditStatementDate": "2018-10-10",
        "StandardAuditPeriodStartDate": "2018-10-10",
        "StandardAuditPeriodEndDate": "2018-10-10",
        "CodeSigningAudit": "",
        "CodeSigningAuditType": "",
        "CodeSigningAuditStatementDate": "",
        "CodeSigningAuditPeriodStartDate": "",
        "CodeSigningAuditPeriodEndDate": "",
        "BRAudit": "",
        "BRAuditType": "",
        "BRAuditStatementDate": "",
        "BRAuditPeriodStartDate": "",
        "BRAuditPeriodEndDate": "",
        "EVSSLAudit": "",
        "EVSSLAuditType": "",
        "EVSSLAuditStatementDate": "",
        "EVSSLAuditPeriodStartDate": "",
        "EVSSLAuditPeriodEndDate": "",
        "EVCodeSigningAudit": "",
        "EVCodeSigningAuditType": "",
        "EVCodeSigningAuditStatementDate": "",
        "EVCodeSigningAuditPeriodStartDate": "",
        "EVCodeSigningAuditPeriodEndDate": ""
    },
    "PolicyInformation": {
        "CPCPSSameAsParent": false,
        "PolicyDocumentation": "",
        "DocumentRepositatory": "https://URL/CA#CPS",
        "CertificatePolicy": "",
        "CertificationPracticeStatement": "https://URL/cps.pdf",
        "CPCPSLastUpdatedDate": "2019-02-01"
    },
    "Description": "",
    "PublicComments": ""
}
```

Any fields that you are not updating can be omitted. At a minimum the `SalesforceRecordId`, `IntermediateCertificateName` and the `IntermediateCertPEM` are required. Setting a field to an empty string clears the value.

`POST https://[SALESFORCE_INSTANCE_URL]/services/apexrest/create/intermediatecert`

```
{
    "CertificateInformation": {
        "SalesforceRecordId": "0010r00000damffAAA",
        "CAOwner": "Digicert",
        "SubordinateCAOwner": "Digicert",
        "IntermediateCertificateName": "Test Intermediate Cert",
        "IntermediateCertPEM": "-----BEGIN CERTIFICATE-----MIIHVDCCBjygAwIBAgIRYUlF+VXF2FWFqCo472HfZlwwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQR2xvYmFsU2lnbiNudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4XDTE0MDUyODAwMDAwMFoXDTE5MDUyODAwMDAwMFoweDELMAkGA1UEBhMCREUxDzANBgNVBAcTBk11bmljaDEeMBwGA1UEChMVR2llc2Vja2UgYW5kIERldnJpZW50MRUwEwYDVQQLQwxDb3Jwb3JhdGUgQ0ExITAfBndeSfw23lzoMYwHwYDVR0jBBgwFoAUFPblizG2RYBKTG38woeJyjbDkGIwDQYJKoZIhvcNAQEFBQADggEBAJATbmLh0flTPZPqd36upxjQcrpDTu6jeMXc1nGruOSmuGnANeyVC6PXU48HKB/BJLvNtyP/1Yzuqe3Y01oEgAYyrYpYBGH4I24gezvgtFF+6J90Ul7cKfup4p0jb2A6jtPSqT5Cu0N2HnONf1VuzL7UTGjJn4Rv6LtIVN3vga0VitKd1jv1RRliRGrY0QJHhL0DwSL1Zjt+Nh/Hm7NoWdKtLzrgzqY4hCvuSEjIa7XWDtTOT6suxvVyZP4l3eURH4eg0kWOJVh97PkwK1S307u/0yx94jirzMnKBfhv/uEXSkPJUu6LwNuWrseosrl9VdGooFT7g/Wf99gsu3iJTf0=-----END CERTIFICATE-----"
    },
    "AuditorInformation": {
        "Auditor": "",
        "AuditorLocation": ""
    },
    "AuditInformation": {
        "AuditSameAsParent": true
    },
    "PolicyInformation": {
        "CPCPSSameAsParent": true
    },
    "Description": "This is the description",
    "PublicComments": "This is the public comment"
}
```

### **Success Response**

If the update request was successful you will receive a HTTP Status Code of `200` with JSON in the body containing the *unique salesforced ID* of the CCADB record that was updated:

```
{
    "ProcessingStatus": "Success",
    "Errors/Warnings": [],
    "SalesforceRecordId": "1394873259327"
}
```

### **Fail Response**
If the update request failed you will receive a HTTP Status Code of `400` with JSON in the body containing information about the failure. If the upload failed because the a record for the PEM already exists, the salesforce record ID of the existing record will also be returned.
```
{
    "ProcessingStatus": "Fail",
    "Errors/Warnings": [
        "The provided Salesforce Record ID and SHA-256 of the provided Intermediate Certificate does not match."
    ],
    "SalesforceRecordId": ""
}
```
