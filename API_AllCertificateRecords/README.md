# AllCertificateRecords REST API


The **AllCertificateRecords REST API V1** is a read-only endpoint that exposes Root and Intermediate Certificate records from the CCADB (Common CA Database) as paginated JSON.

The API **utilizes HTTP `POST` requests** with a JSON request body. This allows you to dynamically choose what extra data to retrieve (via "Field Sets") and apply search filters.

> [!NOTE]
> **We recommend calling the API no more than once per day**. Each API request contributes toward Salesforce API usage limits, so minimizing the number of calls helps conserve available capacity and reduces the risk of reaching platform limits.



## 1. Quick Setup & Endpoints

Use this public / unauthenticated endpoint. No tokens are needed.

- **HTTP Method**: `POST`
- **URL**: `https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords`
 
  **`CCADB_SITE_DOMAIN`**: `ccadb.my.site.com`

- When making a request, specify the following HTTP header to indicate that the request payload is JSON:  
  `-H "Content-Type: application/json; charset=utf-8"`

> [!NOTE]
> For testing in the sandbox environment use **`CCADB_SITE_DOMAIN`**: `ccadb--sbxccadb.sandbox.my.site.com`
>
> Please be mindful that the data in the sandbox environment lags behind production and may not be accurate.


## 2. Request Schema

The `AllCertificateRecordsAPI v1` endpoint expects a JSON request body with the following structure. Passing an empty body `{}` is fully valid and returns the first page of full export (all Root & Intermediate Certificate records).

### Schema Blueprint

```json
{
  "Filters": {
    "NotBeforeYear": 2024,
    "NotBeforeDecade": null,
    "PageNumber": 1
  },
  "FieldSets": [
    "AdditionalCertificateData",
    "Capabilities",
    "AuditorInformation",
    "NonAuditDocumentInformation"
  ]
}
```

### JSON Key Breakdown

#### `Filters` (Object, Conditionally Mandatory)

The filter parameters are optional, if omitted, default values are applied.

| Property | Type | Default | Validation Rules | Description |
| :--- | :--- | :--- | :--- | :--- |
| `NotBeforeYear` | Integer | `null` | `1990` to `2100` | Filters certificates by the calendar year of their `Valid From` date. Takes precedence over `NotBeforeDecade`. Mandatory if `NotBeforeDecade` is not supplied. |
| `NotBeforeDecade` | Integer | `null` | Multiple of 10 (e.g. `2020`), between `1990` and `2100` | Filters certificates by a 10-year range of their `Valid From` date. Ignored if `NotBeforeYear` is supplied. |
| `PageNumber` | Integer | `1` | `≥ 1` | The page number to retrieve. |



## 3. Dynamic Field Sets

The API defaults to sending only core data so it stays fast. To get extra details, you must explicitly request them using the "FieldSets" array.

### Always Included (Core Data)

The following JSON objects are **always** present in the `Data` records:

- **`CertificateInformation`**: Basic identifier details, including Record ID, Name, CA Owner, Parent identity, Record type, Subordinate CA Owner, and Country.
- **`RootStoreStatus`**: Status of the certificate across Apple, Chrome, Microsoft, and Mozilla root stores, and status summary.
- **`CertificateData`**: Validity start/end dates, SHA256 fingerprints, Authority/Subject key identifiers, and Technically Constrained flag.
- **`RevocationInformation`**: Revocation status.



### Additional Data (Optional Data)

An optional list of field set names can be appended to the core payload. Field set names are matched case-insensitively.

**Available Field Sets**:

- `AdditionalCertificateData`
- `TrustInformation`
- `PertainingToCertificatesIssued`
- `AuditorInformation`
- `AuditInformation`
- `PolicyAndDocumentation`
- `NonAuditDocumentInformation`
- `TestWebsites`
- `Capabilities`



### Breakdown of fields in the field sets

1. **`CertificateInformation`**: `CCADBUniqueID`, `CertificateName`, `CAOwner`, `CertificateRecordType`, `ParentCCADBUniqueID`, `ParentCertificateName`, `SubordinateCAOwner`, `Country`
2. **`RootStoreStatus`**: `AppleStatus`, `ChromeStatus`, `MicrosoftStatus`, `MozillaStatus`, `StatusOfRootCert`
3. **`CertificateData`**: `SHA256Fingerprint`, `ParentSHA256Fingerprint`, `ValidFrom`, `ValidTo`, `AuthorityKeyIdentifier`, `SubjectKeyIdentifier`, `TechnicallyConstrained`
4. **`RevocationInformation`**: `RevocationStatus`
5. **`AdditionalCertificateData`**: `TrustBitsForRootCert`, `EVOIDsForRootCert`, `DerivedTrustBits`
6. **`TrustInformation`**: `AppleEVEnabled`, `ExtendedValidationcppOIDs`, `MicrosoftEVSSLEnabled`, `GoogleChromeEVEnabled`, `EVSSLCapable`
7. **`PertainingToCertificatesIssued`**: `JSONArrayOfAllFullCRLURLs`, `JSONArrayOfPartitionedCRLs`, `DVACMEDirectoryURLs`, `OVACMEDirectoryURLs`, `EVACMEDirectoryURLs`, `IVACMEDirectoryURLs`
8. **`AuditorInformation`**: `AuditFirm`, `AuditFirmLocation`
9. **`AuditInformation`**: `AuditSameAsParent` + 7 audit types (`Standard`, `NetSec`, `TLS BR`, `TLS EVG`, `Code Signing`, `S/MIME`, `VMC`), each containing `Audit URL`, `Audit Type`, `Statement Date`, `Period Start Date`, and `Period End Date`.
10. **`PolicyAndDocumentation`**: `PolicyDocumentation`, `CADocumentRepository`, `CPSameAsParent`, `CPSSameAsParent`, `CPCPSSameAsParent`, `MDAsciiDocCPCPSSameAsParent`
11. **`NonAuditDocumentInformation`**: `DocumentLink`, `DocumentType`, `DocumentEffectiveDate`
12. **`TestWebsites`**: `Valid`, `Expired`, `Revoked`
13. **`Capabilities`**: `TLSCapable`, `TLSEVCapable`, `CodeSigningCapable`, `SMIMECapable`



## 4. Sample curl Requests 

### Using one field set

```bash
curl --location 'https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords' \
  --header 'Content-Type: application/json' \
  --data '{
    "Filters": {
      "NotBeforeYear": 2024,
      "PageNumber": 4
    },
    "FieldSets": [
      "Capabilities"
    ]
  }'
```

### Using all field sets

```bash
curl --location 'https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords' \
  --header 'Content-Type: application/json' \
  --data '{
    "Filters": {
      "NotBeforeYear": 2024,
      "NotBeforeDecade": null,
      "PageNumber": 1
    },
    "FieldSets": [
      "AdditionalCertificateData",
      "TrustInformation",
      "PertainingToCertificatesIssued",
      "AuditorInformation",
      "PolicyAndDocumentation",
      "NonAuditDocumentInformation",
      "TestWebsites",
      "Capabilities"
    ]
  }'
```

> [!NOTE]
> Field Set names are **case-insensitive**. If you pass an invalid or unrecognized Field Set name, the API will silently ignore the mismatch and successfully process the rest of the request.



## 5. Pagination — How It Works

The API uses **cursor pagination**. Each response returns a `NextPageNumber` that can be used to request the next page of results. The default page size is 100 records.

### Pagination Metadata

Every response contains a top-level `Meta` object alongside the `Filters` object.

The `Meta.Pagination` object contains the following fields:

| Field | Type | Description |
| :--- | :--- | :--- |
| `TotalRecords` | Integer | Total number of records matching the current filter. |
| `TotalPages` | Integer | Total pages in the filtered dataset. |
| `MaxPageSize` | Integer | Default `100` — maximum record limit per page. Driven by the `CCADB_Settings__c.AllCertRecordsAPI_DefaultPageSize__c` custom setting. |
| `CurrentPageSize` | Integer | The actual number of records returned on this page. |
| `CurrentPageNumber` | Integer | The page number currently requested. |
| `NextPageNumber` | Integer | The next page to request, or `0` if this is the last page. |



## 6. Filtering the Dataset

> [!NOTE]
> The `Filters` block is required to support efficient pagination. Queries that include Long Text Area fields are limited to approximately 100 records per page.

Any request sent without active partitioning filters will return the first page of full export. You should provide `Filters` with `PageNumber` to retrieve subsequent pages. Also, you must provide either `NotBeforeYear` or `NotBeforeDecade` to properly segment the dataset.

You can restrict the search using `NotBeforeYear` or `NotBeforeDecade`:

- **`NotBeforeYear`**: Matches certificates where the `ValidFrom` year matches exactly and must be between `1990` and `2100`.
- **`NotBeforeDecade`**: Matches certificates where the `ValidFrom` year falls within the 10-year decade (e.g., `2020` covers `2020` through `2029`).

> [!NOTE]
> If you provide both `NotBeforeYear` and `NotBeforeDecade`, **`NotBeforeYear` takes precedence** and the decade filter is ignored.

### Example: Filter by Year (2024)

#### curl Request

```bash
curl -X POST "https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{
    "Filters": {
      "NotBeforeYear": 2024
    }
  }'
```



### Example: Filter by Decade (2020s)

#### curl Request

```bash
curl -X POST "https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{
    "Filters": {
      "NotBeforeDecade": 2020
    }
  }'
```



## 7. Pagination in Action (Step-by-Step)

The API returns a maximum of **100 records** per page. To crawl the entire database, you should run a loop in your script.

Let's walk through paginating a dataset containing **350 records** filtered by the decade `2020`:

### Step 1: Fetch Page 1

#### Request

```bash
curl -X POST "https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{
    "Filters": {
      "NotBeforeDecade": 2020,
      "PageNumber": 1
    }
  }'
```

#### Pagination Metadata in Response

```json
{
  "Pagination": {
    "TotalRecords": 350,
    "TotalPages": 4,
    "MaxPageSize": 100,
    "CurrentPageSize": 100,
    "CurrentPageNumber": 1,
    "NextPageNumber": 2
  }
}
```

- **Status**: `NextPageNumber` is **`2`**, meaning there is another page. Proceed to Step 2.



### Step 2: Fetch Page 2

#### Request

Change `PageNumber` in the payload to `2`:

```bash
curl -X POST "https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{
    "Filters": {
      "NotBeforeDecade": 2020,
      "PageNumber": 2
    }
  }'
```

#### Pagination Metadata in Response

```json
{
  "Pagination": {
    "TotalRecords": 350,
    "TotalPages": 4,
    "MaxPageSize": 100,
    "CurrentPageSize": 100,
    "CurrentPageNumber": 2,
    "NextPageNumber": 3
  }
}
```

- **Status**: `NextPageNumber` is **`3`**. Similarly Step 3 will also return you the response. Proceed to Step 3 to fetch the final page.

---

### Step 3: Fetch Page 4 (The Final Page)

#### Request

Change `PageNumber` in the payload to `4`:

```bash
curl -X POST "https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{
    "Filters": {
      "NotBeforeDecade": 2020,
      "PageNumber": 4
    }
  }'
```

#### Pagination Metadata in Response

```json
{
  "Pagination": {
    "TotalRecords": 350,
    "TotalPages": 4,
    "MaxPageSize": 100,
    "CurrentPageSize": 50,
    "CurrentPageNumber": 4,
    "NextPageNumber": 0
  }
}
```

- **Status**: `NextPageNumber` is **`0`**. This signals that **no more pages are available**. You have completed the harvest.
- Notice that `CurrentPageSize` is `50` since only the remaining 50 records were loaded.



## 8. Error Scenarios & Troubleshooting

All API validation failures return an **HTTP status code 400 (Bad Request)** or **500 (Server Error)**. The response body is formatted using the exact same JSON envelope, making it easy for your parsing scripts to handle.

Here are the specific scenarios to test:

### Error Scenario A: Invalid JSON Structure

- **Trigger**: Sending an unparseable JSON payload (e.g., missing a bracket).
- **Test Payload**:

```json
{
  "Filters": {
    // missing closing bracket
```

- **curl Request**:

```bash
curl -X POST "https://{CCADB_SITE_DOMAIN}/services/apexrest/v1/allcertificaterecords" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{"Filters": {"PageNumber": 1'
```

- **Response (HTTP 400)**:

```json
{
  "Status": "Error",
  "Message": "Invalid JSON body: Unexpected end-of-input: expected close marker for OBJECT (from [line:3, column:22]",
  "Meta": {
    "Date/Time": "2026-07-29T13:40:17Z",
    "Pagination": {
      "TotalRecords": 0,
      "TotalPages": 0,
      "MaxPageSize": 0,
      "CurrentPageSize": 0,
      "CurrentPageNumber": 0,
      "NextPageNumber": 0
    }
  },
  "Filters": {
    "NotBeforeYear": null,
    "NotBeforeDecade": null,
    "PageNumber": 0
  },
  "Data": []
}
```



### Error Scenario B: Invalid Page Number (Less Than 1)

- **Trigger**: Sending a `PageNumber` of `0` or a negative number.
- **Test Payload**:

```json
{
  "Filters": {
    // "NotBeforeYear": 2020, // one of this filter is required
    "NotBeforeDecade": 2020, // NotBeforeDecade out of range
    "PageNumber": 0 // change the page numbers in every request
  },
  "FieldSets": []
}
```

- **Response (HTTP 400)**:

```json
{
  "Status": "Error",
  "Message": "PageNumber must be >= 1.",
  "Meta": {
    "Date/Time": "2026-07-29T13:39:02Z",
    "Pagination": {
      "TotalRecords": 0,
      "TotalPages": 0,
      "MaxPageSize": 0,
      "CurrentPageSize": 0,
      "CurrentPageNumber": 0,
      "NextPageNumber": 0
    }
  },
  "Filters": {
    "NotBeforeYear": null,
    "NotBeforeDecade": 2020,
    "PageNumber": 0
  },
  "Data": []
}
```



### Error Scenario C: NotBeforeYear Out of Range

- **Trigger**: Input year is outside the supported calendar range (`1990` - `2100`).
- **Test Payload**:

```json
{
  "Filters": {
    // "NotBeforeYear": 2020, // one of this filter is required
    "NotBeforeDecade": 2226, // NotBeforeDecade out of range
    "PageNumber": 1 // change the page numbers in every request
  },
  "FieldSets": []
}
```

- **Response (HTTP 400)**:

```json
{
  "Status": "Error",
  "Message": "NotBeforeDecade must be a decade start (e.g. 1990, 2000) between 1990 and 2100.",
  "Meta": {
    "Date/Time": "2026-07-29T13:38:10Z",
    "Pagination": {
      "TotalRecords": 0,
      "TotalPages": 0,
      "MaxPageSize": 0,
      "CurrentPageSize": 0,
      "CurrentPageNumber": 0,
      "NextPageNumber": 0
    }
  },
  "Filters": {
    "NotBeforeYear": null,
    "NotBeforeDecade": 2226,
    "PageNumber": 0
  },
  "Data": []
}
```



### Error Scenario D: NotBeforeDecade is Not a Decade Start

- **Trigger**: Input decade is not a multiple of 10 or is out of range.
- **Test Payload**:

```json
{
  "Filters": {
    // "NotBeforeYear": 2020, // one of this filter is required
    "NotBeforeDecade": 2026, // Providing invalid NotBeforeDecade
    "PageNumber": 1 // change the page numbers in every request
  },
  "FieldSets": []
}
```

- **Response (HTTP 400)**:

```json
{
  "Status": "Error",
  "Message": "NotBeforeDecade must be a decade start (e.g. 1990, 2000) between 1990 and 2100.",
  "Meta": {
    "Date/Time": "2026-07-29T13:36:06Z",
    "Pagination": {
      "TotalRecords": 0,
      "TotalPages": 0,
      "MaxPageSize": 0,
      "CurrentPageSize": 0,
      "CurrentPageNumber": 0,
      "NextPageNumber": 0
    }
  },
  "Filters": {
    "NotBeforeYear": null,
    "NotBeforeDecade": 2026,
    "PageNumber": 0
  },
  "Data": []
}
```



### Error Scenario E: Page Number Out of Bounds

- **Trigger**: Requesting a page index higher than the calculated `TotalPages`.
- **Test Payload**:

```json
{
  "Filters": {
    // "NotBeforeYear": 2020, // one of this filter is required
    "NotBeforeDecade": 2020,
    "PageNumber": 9999 // Page Number out of bound
  },
  "FieldSets": [
    "AdditionalCertificateData",
    "AuditorInformation",
    "AuditInformation",
    "IssuanceRevocationEndpoints",
    "PertainingToCertificatesIssued",
    "PolicyAndDocumentation",
    "TestWebsites",
    "TrustInformation",
    "Capabilities",
    "NonAuditDocumentInformation"
  ]
}
```

- **Response (HTTP 400)**:

```json
{
  "Status": "Error",
  "Message": "PageNumber (9999) exceeds TotalPages (39).",
  "Meta": {
    "Date/Time": "2026-07-29T13:31:25Z",
    "Pagination": {
      "TotalRecords": 3819,
      "TotalPages": 0,
      "MaxPageSize": 0,
      "CurrentPageSize": 0,
      "CurrentPageNumber": 0,
      "NextPageNumber": 0
    }
  },
  "Filters": {
    "NotBeforeYear": null,
    "NotBeforeDecade": 2020,
    "PageNumber": 0,
    "RequestedFieldSets": [
      "AdditionalCertificateData",
      "AuditorInformation",
      "AuditInformation",
      "PertainingToCertificatesIssued",
      "PolicyAndDocumentation",
      "TestWebsites",
      "TrustInformation",
      "Capabilities",
      "NonAuditDocumentInformation"
    ]
  },
  "Data": []
}
```
