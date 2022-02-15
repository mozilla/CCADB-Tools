# CCADB APIs

CCADB APIs have been developed to allow Certification Authorities (CAs) to retrieve and update data in the CCADB, enabling CAs to automate the process of uploading their intermediate certificates. The REST API accepts JSON payloads and it is integrated via Salesforce Connected App. This service is only available to CAs whose root and intermediate certificates are included within the products and services of CCADB root store members.  

1. **GetCertificateIdAPI** https:/[HOST_URL]/services/apexrest/get/recordid
	Returns the root or intermediate certificate record Id (Salesforce Id) in the CCADB.
	
2. **AddUpdateIntermediateCertAPI** https:/[HOST_URL]/services/apexrest/create/intermediatecert
	Add or update an intermediate certificate record in the CCADB.
 
## Example
Scripts have been provided at https://github.com/HARICA-official/ccadb-ca-tools to demonstrate how to use the API to update the "Full CRL Issued By This CA" field for intermediate certificate records.

## API Authentication

OAuth 2 protocol is used to authorize the callouts made by the client application to grant restricted access data to the protected resources in CCADB database. Only a pre configured API enabled CA Community User will be used for callouts. The API details (HOST_URL, CONSUMER_KEY, CONSUMER_SECRET, etc.) will be provided by the CCADB administrator to complete the authentication process described below:

1. Login to CCADB using the CA Community User credentials
2. Replace the parameters in the link below and paste it in the address bar of your browser
	https://[HOST_URL]/services/oauth2/authorize?client_id=[CONSUMER_KEY]&redirect_uri=https://[HOST_URL]/&response_type=code
3. An approval page will be displayed to grant access to the app. Click on the 'Allow' button to approve 
4. Salesforce will redirect to the callback url (specified in 'redirect_uri'). Quickly freeze the loading of the page and look in the browser address bar to extract the 'authorization code', save the code for the next steps. The link will look like the one below:
https://[HOST_URL]/?code=a2KQxyzYaMm_hIxxxxxxxxxxbKd9zxxxxxtWyvLViTsgg%3D%3D&sfdc_community_url=https://[HOST_URL]&sfdc_community_id=0ABC000ABC0KzhXYZC
5. To get refresh tokens use Postman or another tool that can make REST API calls. Set a single POST request and pass the parameters below:

	POST request endpoint: [https://[HOST_URL]/services/oauth2/token

    |Key| Value |
    |--|--|
    |client_id|[CONSUMER_KEY]|
    |client_secret|[CONSUMER_SECRET]|
    |grant_type|authorization_code|
    |code  | [AUTHORIZATION_CODE] |
    |redirect_uri|https://[HOST_URL]/|

     **Important**: *The AUTHORIZATION_CODE should only be used once or you will have to start the process over again in the browser.*

      If the POST request is successful, you will receive a JSON response that looks like this:
    ```
    {
    "access_token": "Ml84H6WahE......5ce8S8i0g6B8EuakeIK",
    "refresh_token": "2x8rydH234.......AmED2LdYZj9YqsTl",
    "sfdc_community_url": "https://[HOST_URL]",
    "sfdc_community_id": "WK6234000ACDFaMXYZ",
    "signature": "l456fgWR3FOkQwp23456xVaVqRS",
    "scope": "visualforce refresh_token web api full",
    "id_token": "https://ccadb..salesforce.com/id/00123.78/00789..55",
    "issued_at": "1098905410916"
   }
    ```
     From the response body copy the 'access token' and 'refresh token'.  'access token' is used to make subsequent authentication calls. 'refresh token' is used each time you need to get the access token.

6. Once you have the 'refresh token' it can be reused for subsequent API authentication requests. Whenever API operations are needed you will first need to send an authentication request to retrieve a temporary bearer token that will need to be included in every API request.

    To authenticate and retrieve a new bearer token send a POST request to the same authentication endpoint  POST https://[HOST_URL]/services/oauth2/token with the following POST variables:
    
    |Key| Value |
    |--|--|
    |client_id|[CONSUMER_KEY]|
    |client_secret|[CONSUMER_SECRET]|
    |grant_type|refresh_token|
    |refresh_token|[REFRESH_TOKEN]|

    JSON response
    ```
    {
    "access_token": "00D0m000.............qw8tLS_tTRaD",
    "sfdc_community_url": "https://[SALESFORCE_INSTANCE_URL]",
    "sfdc_community_id": "WK...AGDC",
    "signature": "aHwST5cMLB63XBSmalnay9QR0TLt7Mc/DGB9kT1MuFc=",
    "scope": "refresh_token visualforce web api full",
    "instance_url": "[SALESFORCE_INSTANCE_URL]",
    "id": "https://[SALESFORCE_INSTANCE_URL]/id/00D0r..OAA/0040..AAY",
    "token_type": "Bearer",
    "issued_at": "1608173806332"
    }
    ```

## CCADB GetCertificateIdAPI Processing Requirements

GetCertificateIdAPI returns a root or intermediate certificate record Id (Salesforce Id) in the CCADB. The JSON Request must provide a record type (Root Certificate/Intermediate Certificate) along with the PEM or the SHA-256 Fingerprint of the certificate. If the criteria is found, an 18 digit Salesforce record Id is returned with 'Success' status. 

### Processing Highlights

If the PEM of the certificate is provided, the PEM is parsed to extract the SHA-256 Fingerprint of the certificate. 
 
When both the certificate's PEM and SHA-256 Fingerprint are provided, and if the SHA-256 Fingerprint does not match the one that was provided, a failed status is returned.

If more than one certificate of the specified type (e.g. Intermediate Certificate) is found in the CCADB with the same SHA-256 Fingerprint, the record id of the first record found is returned.

### JSON Request/Response Definition
```
Request Body: 
{ 
    Sring PEM,   # pass PEM string with no carriage return/linefeed; field is populated only during record creation, updates cannot be done via this API (can be done directly in CCADB)
    String SHA256, 
    String RecordType  # valid values "Root Crtificate" or "Intermediate Certificate"
} 

Response Body: 
 {
    String ProcessingStatus;   # Fail, Success, SuccessWithWarnings
    List <Errors/Warnings> Errors/Warnings;
    String RecordId; 
 } 
```

### JSON Definition Samples

```
[SUCCESS] Request Body: 
{
    "PEM":"-----BEGIN CERTIFICATE-----MIIHVDCCBjygAwIBAgIRYUlF+VXF2FWFqCo472HfZlwwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQR2xvYmFsU2lnbiNudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4XDTE0MDUyODAwMDAwMFoXDTE5MDUyODAwMDAwMFoweDELMAkGA1UEBhMCREUxDzANBgNVBAcTBk11bmljaDEeMBwGA1UEChMVR2llc2Vja2UgYW5kIERldnJpZW50MRUwEwYDVQQLQwxDb3Jwb3JhdGUgQ0ExITAfBgMVBAMTGEdpZXNlY2tlIGFuZCBEZXZyaWVudCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANWu5Jjc3fah78pqjmfQwOiEti0wkb/YyoBxahiMcyLmNybDCBhAYIKwYBBQUHAQEEeDB2MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vdHJ1c3Ryb290ZzIwPwYIKwYBBQUHMAKGM2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3RydXN0cm9vdGcyLmNydDAdBgNVHQ4EFgQU5mi9zkOA6ddzO7ndeSfw23lzoMYwHwYDVR0jBBgwFoAUFPblizG2RYBKTG38woeJyjbDkGIwDQYJKoZIhvcNAQEFBQADggEBAJATbmLh0flTPZPqd36upxjQcrpDTu6jeMXc1nGruOSmuGnANeyVC6PXU48HKB/BJLvNtyP/1Yzuqe3Y01oEgAYyrYpYBGH4I24gezvgtFF+6J90Ul7cKfup4p0jb2A6jtPSqT5Cu0N2HnONf1VuzL7UTGjJn4Rv6LtIVN3vga0VitKd1jv1RRliRGrY0QJHhL0DwSL1Zjt+Nh/Hm7NoWdKtLzrgzqY4hCvuSEjIa7XWDtTOT6suxvVyZP4l3eURH4eg0kWOJVh97PkwK1S307u/0yx94jirzMnKBfhv/uEXSkPJUu6LwNuWrseosrl9VdGooFT7g/Wf99gsu3iJTf0=-----END CERTIFICATE-----",
    "SHA256":"663C9FDA690A98A29EDEA34B8C9C7C664D0AEAC635056E56CDA14D28D7CB155B",
    "RecordType": "Intermediate Certificate"
}
Response Body: 
{
    "ProcessingStatus": "Success",
    "Errors/Warnings": [],
    "RecordId": "0010r00000UqC4AAAV"
}


[FAILURE] Request Body:
{
    "PEM":"-----BEGIN CERTIFICATE-----MIIHVDCCBjygAwIBAgIRYUlF+VXF2FWFqCo472HfZlwwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQR2xvYmFsU2lnbiNudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4XDTE0MDUyODAwMDAwMFoXDTE5MDUyODAwMDAwMFoweDELMAkGA1UEBhMCREUxDzANBgNVBAcTBk11bmljaDEeMBwGA1UEChMVR2llc2Vja2UgYW5kIERldnJpZW50MRUwEwYDVQQLQwxDb3Jwb3JhdGUgQ0ExITAfBgMVBAMTGEdpZXNlY2tlIGFuZCBEZXZyaWVudCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANWu5Jjc3fah78pqjmfQwOiEti0wkb/YyoBxahiMcyLmNybDCBhAYIKwYBBQUHAQEEeDB2MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vdHJ1c3Ryb290ZzIwPwYIKwYBBQUHMAKGM2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3RydXN0cm9vdGcyLmNydDAdBgNVHQ4EFgQU5mi9zkOA6ddzO7ndeSfw23lzoMYwHwYDVR0jBBgwFoAUFPblizG2RYBKTG38woeJyjbDkGIwDQYJKoZIhvcNAQEFBQADggEBAJATbmLh0flTPZPqd36upxjQcrpDTu6jeMXc1nGruOSmuGnANeyVC6PXU48HKB/BJLvNtyP/1Yzuqe3Y01oEgAYyrYpYBGH4I24gezvgtFF+6J90Ul7cKfup4p0jb2A6jtPSqT5Cu0N2HnONf1VuzL7UTGjJn4Rv6LtIVN3vga0VitKd1jv1RRliRGrY0QJHhL0DwSL1Zjt+Nh/Hm7NoWdKtLzrgzqY4hCvuSEjIa7XWDtTOT6suxvVyZP4l3eURH4eg0kWOJVh97PkwK1S307u/0yx94jirzMnKBfhv/uEXSkPJUu6LwNuWrseosrl9VdGooFT7g/Wf99gsu3iJTf0=-----END CERTIFICATE-----",
    "SHA256":"663C9FDA690A98A29EDEA34B8C9C7C664D0AEAC635056E56CDA14D28D7CB155Bx",
    "RecordType": "Intermediate Certificate"
}

Response Body: 
 {
    "ProcessingStatus": "Fail",
     "Errors/Warnings": ["Certificate not found in CCADB."],
     "RecordId": ""
 } 

```

## CCADB AddUpdateIntermediateCertAPI Processing Requirements

AddUpdateIntermediateCertAPI may be used to either add a new record to the CCADB, or update an existing CCADB record. To update an existing intermediate certificate record, the JSON request must have the certificate's PEM and the 18 digit Salesforce Certificate Record ID. To add an intermediate certificate record, the JSON request must provide the PEM of the certificate to be added along with PEM of the certificate that signed it (i.e. it's parent certificate). If any attributes fail to meet the criteria (see below for field level checks), a list of errors/warnings is compiled and sent to the user as part of JSON Response. 

### Processing Highlights

-   CAs can only add or update certificiates in their CA's hierarchy.
-   If the Salesforce Record Id is populated (with 18 digit id) then it is considered to be an 'update' request or else it is assumed to be an 'add' request.
-   IntermediateCertPEM and ParentCertPEM are parsed by an extraction tool provided by TLS Observatory.
-   CAOwner PEM in the request must be the PEM of the certificate that signed the certificate to be added (i.e. the parent certificate), and the parent certificate must already have a corresponding record in the CCADB. 
-   For an 'add' request the CA Owner + SHA-256 Fingerprint must be unique, otherwise an error is returned regarding duplicate records.
-   For an 'update' request, the SHA-256 Fingerprint is extracted from IntermediateCertPEM and checked against the Salesforce record (SalesforceRecordId passed in the request), if the SHA-256 Fingerprint does not match the value in the record, then the record is not updated and an error message is returned.
-   For an 'update' request, fields with 'null' values are ignored. If the fields have blank '' value, then the corresponding Salesforce fields are set to blank. This rule applies to all field types such as text, date, picklist, url and lookup.
-   This API does not allow CAs to update IntermediateCertPEM and ParentCertPEM fields.
-   All attributes are validated within this controller class and a list of errors/warnings are returned as part of the response for CAs to correct the data.
-   The data for picklist fields is validated dynamically (Eg: Revocation Status, Audit Type fields) which means if the picklist field values in the CCADB are updated, the program will fetch the latest values for validation.
-   A new object 'API Log' will track every add/update request and response along with the user information.
-   ALV processing is not done at the time of add or update. The CCADB has a separate process that regularly checks for added or updated intermediate certificates and runs ALV on them.
-   If additional validations or trigger logic is added to process intermediate certificate records, this controller class must also be reviewed to incorporate those changes.

### Mandatory Fields

-   Add New Cert: CAOwner, IntermediateCertificateName, IntermediateCertPEM, ParentCertPEM
-   Update Existing Cert Record: SalesforceRecordId, CAOwner, IntermediateCertificateName, IntermediateCertPEM
 
### JSON Request Definition
```
 Class CertificateInformation {
     String SalesforceRecordId;              # 18 digit Salesforce record id is required when callout is made for update; Salesforce id is returned upon successful add request
     String CAOwner;                         # required field; add/update actions allowed only on CAs own hierarchy
     String SubordinateCAOwner;             
     String IntermediateCertName;            # the value should be Subject CN of the cert for add/update callouts; it is also being used for tracking API calls and reporting; not used for any validations
     String IntermediateCertPEM;             # required field; pass PEM string with no carriage return/linefeed; field is populated only during record creation, updates cannot be done via this API (can be done directly in CCADB)
     String ParentCertPEM;                   # required field; pass PEM string with no carriage return/linefeed; field is populated only during record creation, updates cannot be done via this API (can be done directly in CCADB)
     Boolean ConsentforTechnicallyConstrainedCert   # set the field to True when the cert is technically constrained 
 }
 Class RevocationInformation {
     String RevocationStatus;                # Date format yyyy-MM-dd; leave empty/null if certificate is not revoked, otherwise set to 'Revoked'
     String DateOfRevocation;                # when Revocation Status is 'Revoked', provide a valid date inm format yyyy-MM-dd
     String RevocationReasonCode;            # when provided, use one of the RFC 5280 Revocation Reason Code available in the CCADB
     String AlternateCRL;              
 }
 Class OtherCAInformation {
    String RecognizedCAADomains;
    String ProblemReportingMechanism;
 }
 Class PertainingToCertificatesIssued { 
    String FullCRLIssuedByThisCA;            # can be null or a link  
    List<string> JSONArrayofPartitionedCRLs  # Can be null or a JSON Array of strings; no action taken on this field when value is null; when value is [] the field is reset to empty; field has 20,000 characters limit
}
 Class AuditorInformation {
    String Auditor;                          # can be null or the name of an Auditor in the CCADB list of all auditors
    String AuditorLocation;                  # can be null or the name of one of the Auditor's Locations in the CCADB list of all auditors
 } 
 Class AuditInformation {
    Boolean AuditSameAsParent;               # can be null or set to True if the new cert will be in the parent cert's annual audit statements   
    String StandardAudit;                    # valid https url 
    String StandardAuditType;                # when StandardAudit is provided, tyep must be one of the Audit Types available in the CCADB
    String StandardAuditStatementDate;       # when StandardAudit is provided, date must be in format yyyy-MM-dd
    String StandardAuditPeriodStartDate;     # when StandardAudit is provided, date must be in format yyyy-MM-dd
    String StandardAuditPeriodEndDate;       # when StandardAudit is provided, date must be in format yyyy-MM-dd;
                                                 End Date cannot be > Statement Date; End Date should be > or = to Period Start Date
                                                    
    String CodeSigningAudit;                 # valid https url 
    String CodeSigningAuditType;             # when CodeSigningAudit is provided, type must be one of the Audit Types available in the CCADB
    String CodeSigningAuditStatementDate;    # when CodeSigningAudit is provided, date must be in format yyyy-MM-dd
    String CodeSigningAuditPeriodStartDate;  # when CodeSigningAudit is provided, date must be in format yyyy-MM-dd
    String CodeSigningAuditPeriodEndDate;    # when CodeSigningAudit is provided, date must be in format yyyy-MM-dd; 
                                                 End Date cannot be > Statement Date; End Date should be > or = to Period Start Date,

    String BRAudit;                          # valid https url 
    String BRAuditType;                      # when BRAudit is provided, type must be one of the Audit Types available in the CCADB
    String BRAuditStatementDate;             # when BRAudit is provided, date must be in format yyyy-MM-dd
    String BRAuditPeriodStartDate;           # when BRAudit is provided, date must be in format yyyy-MM-dd
    String BRAuditPeriodEndDate;             # when BRAudit is provided, date must be in format yyyy-MM-dd; 
                                                 End Date cannot be > Statement Date; End Date should be > or = to Period Start Date,
    
    String EVSSLAudit;                       # valid https url 
    String EVSSLAuditType;                   # when EVSSLAudit is provided, type must be one of the Audit Types available in the CCADB
    String EVSSLAuditStatementDate;          # when EVSSLAudit is provided, date must be in format yyyy-MM-dd
    String EVSSLAuditPeriodStartDate;        # when EVSSLAudit is provided, date must be in format yyyy-MM-dd
    String EVSSLAuditPeriodEndDate;          # when EVSSLAudit is provided, date must be in format yyyy-MM-dd; 
                                                 End Date cannot be > Statement Date; End Date should be > or = to Period Start Date
                                                    
    String EVCodeSigningAudit;               # valid https url 
    String EVCodeSigningAuditType;           # when EVCodeSigningAudit is provided, type must be one of the Audit Types available in the CCADB
    String EVCodeSigningAuditStatementDate;  # when EVCodeSigningAudit is provided, date must be in format yyyy-MM-dd
    String EVCodeSigningAuditPeriodStartDate;# when EVCodeSigningAudit is provided, date must be in format yyyy-MM-dd
    String EVCodeSigningAuditPeriodEndDate;  # when EVCodeSigningAudit is provided, date must be in format yyyy-MM-dd; 
                                                 End Date cannot be > Statement Date; End Date should be > or = to Period Start Date
 }
 
 Class PolicyInformation {
    Boolean CPCPSSameAsParent                # can be null or set to True if the new cert will be in the parent cert's CP/CPS info
    String PolicyDocumentation;
    String DocumentRepository;
    String CertificatePolicy;
    String CertificationPracticeStatement;
    String CPCPSLastUpdatedDate;             # when provided, date must be in format yyyy-MM-dd
 }

  String Description;
  String PublicComments;
}
```

### JSON Response Definition

```
 {
    String ProcessingStatus;              # Fail, Success, SuccessWithWarnings
    List <Errors/Warnings> Errors/Warnings;
    String SalesforceRecordId; 
 } 
```

### JSON Definition Sample to Add Intermediate Cert
```
Request Body:
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
   "PertainingToCertificatesIssued": {  
      "FullCRLIssuedByThisCA": "" ,
      "JSONArrayofPartitionedCRLsByCA":
           [  
           "[http://cdn.example/crl-1.crl](http://cdn.example/crl-1.crl)",  
           "[http://cdn.example/crl-2.crl](http://cdn.example/crl-2.crl)"  
           ]        
  },
    "AuditorInformation": {
        "Auditor": "Auditor Name",
        "AuditorLocation": "United States"
    },
    "AuditInformation": {
        "AuditSameAsParent": false,
        "StandardAudit": "http://URL/StandardAudit04FINAL.PDF",
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

Success Response Body (If the upload request was successful you will receive a HTTP Status Code of `200` with JSON in the body containing the unique salesforced ID of the CCADB record that was created): 
{
    "ProcessingStatus": "Success",
    "Errors/Warnings": [],
    "SalesforceRecordId": "0010r00000damffAAA"
}

Failed Response Body (If the upload request failed you will receive a HTTP Status Code of `400` with JSON in the body containing information about the failure. If the upload failed because the a record for the PEM already exists, the salesforce record ID of the existing record will also be returned.):
{
    "ProcessingStatus": "Fail",
    "Errors/Warnings": ["This Intermediate Certificate already exists in CCADB."],
    "SalesforceRecordId": "0010r00000damffAAA"
}

```

### JSON Definition Sample to Update Existing Intermediate Cert

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

Success Response Body:

{
    "ProcessingStatus": "Success",
    "Errors/Warnings": [],
    "SalesforceRecordId": "1300870009327"
}

Failed Response Body:

{
    "ProcessingStatus": "Fail",
    "Errors/Warnings": [
        "The provided Salesforce Record ID and SHA-256 of the provided Intermediate Certificate does not match."
    ],
    "SalesforceRecordId": ""
}
```

```
