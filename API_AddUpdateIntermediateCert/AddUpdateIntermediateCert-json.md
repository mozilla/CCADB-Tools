# CCADB AddUpdateInterermediateCertAPI 
This API has been developed to allow external parties to add or update intermediate certificates in CCADB. The REST API  accepts JSON payloads and it is integrated via Salesforce Connected App.  This service is available only to the CAs (Certification Authorities) who are currently in CCADB to automate the process of uploading their intermediate certificates. 

## Authentication
Oauth 2 protocol will authorize the callouts made by client application to grant restricted access data to the protected resources in CCADB database. Only a pre-configured API enabled community user will be used for callouts. 

## Processing Requirements
To add an intermediate certificate, the JSON Request should provide valid PEM info along with Parent PEM info. If other attributes fail to meet the criteria (see below for field level checks), a list of errors/warnings is compiled and sent to the user as part of JSON Response. However, to update an intermediate certificate, JSON request should have valid PEM and 18 digit Salesforce Record ID.

## Processing Highlights
- If the Salesforce Record Id is populated (with 18 digit id) then it is considered to be an 'update' request  or else it is assumed to be an 'add' request.  
- IntermediateCertPEM and ParentCertPEM are parsed by an extraction tool provided by TLS Observatory.  
- CAOwner from the request must match the ParentIntermediateCert CA Owner. CAs can only add/update certs  which are in their hierarchy.  
- For an 'add' request the CA Owner + SHA-256 must be unique, otherwise an error is returned regarding duplicate records.
- For an 'update' request, SHA-256 is extracted from IntermediateCertPEM and checked against the Salesforce  record (SalesforceRecordId pass in the request), if SHA-256 does not match then the record is not updated  and an error message is returned.  
- For an 'update' request, fields with 'null' values are ignored. If the fields have blank '' value, then the  corresponding Salesforce fields are set to blank. This rule applies to all field types such as  text, date, picklist, url and lookup.  
- This API does not allow CAs to update IntermediateCertPEM and ParentCertPEM fields.  
- All attributes are validated within this controller class and a list of errors/warnings are returned as part of the response for CAs to correct the data.  
- The data for picklist fields is validated dynamically (Eg: Revocation Status, Audit Type fields) which means if the picklist field values in SF are updated, the program will fetch the latest values for validation.  
- A new object 'API Log' will track every add/update request and response along with the user info.  
- ALV processing is not done at the time of add/update intermediate cert. The CCADB has a separate process that regularly checks for added/updated intermediate certificates and runs ALV on them.
- If additional validations or trigger logic is added to process intermediate cert, this controller class must also be reviewed to incorporate those changes.

## JSON Request Definition

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

## JSON Response Definition
```
 {
    String ProcessingStatus;              # Fail, Success, SuccessWithWarnings
    List <Errors/Warnings> Errors/Warnings;
    String SalesforceRecordId; 
 } 
```
