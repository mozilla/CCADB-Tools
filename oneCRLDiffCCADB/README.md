# oneCRLDiffCCADB

`oneCRLDiffCCADB` compares the "OneCRL Status" field from each certificate in [PublicIntermediateCertsRevokedWithPEMCSV](https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV) and attempts to find it within [OneCRL](https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records).

|                 | Added to OneCRL | Cert Expired | Ready to Add | Absent from CCADB |
| :-------------: | :-------------: | :----------: | :----------: | :----------------: |
| Present in OneCRL     | ✅ | ❌ | ❌ | ❌ |
| Absent from OneCRL    | ❌ | ✅ | ✅ | ✅ |


 ...where a ✅ is typically considered fine and a ❌ is considered an error case, although
 this tool does not do any deeper interpretation than merely providing the results
 of building this table.
 
 ### Deployment
 
 #### Locally
 When running `oneCRLDiffCCADB` locally:
 
         $ go build -o oneCRLDiffCCADB .
         $ PORT=8080 ./oneCRLDiffCCADB
 
 #### Using Docker
 Alternatively, one may use the provided `Dockerfile` and `Makefile`:
 
         $ make clean build run
         
 ### Usage
 
 This tool has only one endpoint at `/` (E.G `curl http://localhost:8080/`)
 
 ```go
type Entry struct {
	Serial                 string `csv:"Certificate Serial Number" json:"serial"`
	RevocationStatus       string `csv:"OneCRL Status" json:"revocationStatus"`
	IssuerCommonName       string `csv:"Certificate Issuer Common Name" json:"issuerCN"`
	IssuerOrganizationName string `csv:"Certificate Issuer Organization" json:"issuerON"`
	Fingerprint            string `csv:"SHA-256 Fingerprint" json:"fingerprint"`
}
type OneCRLIntermediate struct {
	Schema  int `json:"schema"`
	Details struct {
		Bug     string `json:"bug"`
		Who     string `json:"who"`
		Why     string `json:"why"`
		Name    string `json:"name"`
		Created string `json:"created"`
	} `json:"details"`
	Enabled      bool   `json:"enabled"`
	IssuerName   Name   `json:"issuerName"`
	SerialNumber string `json:"serialNumber"`
	Id           string `json:"id"`
	LastModified int    `json:"last_modified"`
}

type Normalized struct {
	*ccadb.Entry
	*oneCRL.OneCRLIntermediate
}

// The final return object of the / endpoint.
type Return struct {
	// "Added to OneCRL" and present in OneCRL
	AddedAndPresentInOneCRL []*normalized.Normalized
	// "Cert Expired" and present in OneCRL
	ExpiredAndPresentInOneCRL []*normalized.Normalized
	// "Ready to Add" and present in OneCRL
	ReadyToAddAndPresentInOneCRL []*normalized.Normalized
	// No such record in the CCADB, however exists in OneCRL
	AbsentFromCCADBAndPresentInOneCRL []*normalized.Normalized

	// "Added to OneCRL" and not present in OneCRL
	AddedAndAbsentFromOneCRL []*normalized.Normalized
	// "Cert Expired" and not present in OneCRL
	ExpiredAndAbsentFromOneCRL []*normalized.Normalized
	// "Ready to Add" and not present in OneCRL
	ReadyToAddAndAbsentFromOneCRL []*normalized.Normalized

	// Not present in either. This is not really possible
	// for this tool to know, however it is worth having
	// for the sake of being explicit, I suppose.
	AbsentFromCCADBAndAbsentFromOneCRL []*normalized.Normalized
	// A record in the CCADB was found whose "OneCRL Status"
	// is the empty string.
	NoRevocationStatus []*normalized.Normalized
}
```

For example:

```json
{
  "AddedAndPresentInOneCRL": [
    {
      "serial": "272B67229745D2438BF9774186AEBD",
      "revocationStatus": "Added to OneCRL",
      "issuerCN": "SwissSign Gold CA - G2",
      "issuerON": "SwissSign AG",
      "fingerprint": "B102959F862B71B78EFDC7FA9F43B3AFD7E52312A07493A752835B991D840F4C"
    },
    {
      "serial": "5E6A370085B654779E268474A34F5119",
      "revocationStatus": "Added to OneCRL",
      "issuerCN": "VeriSign Class 3 Public Primary Certification Authority - G5",
      "issuerON": "VeriSign, Inc.",
      "fingerprint": "7E12646B4C25257479ECDC4FBEDFA5225BF5C4520301EABB1FFFA2566C932560"
    },
    {
      "serial": "01313B3B",
      "revocationStatus": "Added to OneCRL",
      "issuerCN": "Staat der Nederlanden Burger CA - G2",
      "issuerON": "Staat der Nederlanden",
      "fingerprint": "DA89E17721513690FE115F5C23F0CB76B6D6E258540A85F8537511EA720056C6"
    },
    {
      "serial": "00F85D2F190C609F1494B28DF9C1D1E74C",
      "revocationStatus": "Added to OneCRL",
      "issuerCN": "TeliaSonera Root CA v1",
      "issuerON": "TeliaSonera",
      "fingerprint": "CEDBC6EEE71BBE0D4EE5A728B4215A4C634C654D44F737F2E3BA35E0A295FBF4"
    },
   ....
  ]
}
```