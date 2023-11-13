certdataDiffCCADB
-------------------------------
This tool finds the differences between a given `certdata.txt` file and the contents of a CCADB PEM report.

The three "buckets" of output are:

* Matched, wherein the entries are both in `certdata.txt` as well as the CCADB
* Unmatched and Trusted, wherein the entries are either in `certdata.txt` or in the CCADB but NOT in both AND their trust bits are set to `true`.
* Unmatched and Untrusted, wherein the entries are either in `certdata.txt` or in the CCADB but NOT in both AND their trust bits are set to `false`.


Usage
-------------------------------
```
Usage of ./certdataDiffCCADB:
  -ccadb string
    	Path to CCADB report file.
  -ccadburl string
    	URL to CCADB report file. (default "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV")
  -cd string
    	Path to certdata.txt
  -cdurl string
    	URL to certdata.txt (default "https://hg.mozilla.org/releases/mozilla-beta/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt")
  -o string
    	Path to the output directory.
  -serve
    	Start in server mode. While in server mode the /certdata endpoint is available which downloads a copy of certdata.txt from the default URL and returns a simplified JSON representation. This option requires that the PORT environment variable be set.
```

__Examples:__

* Output three JSON files (matched.json, unmatchedTrusted.json, and unmatchedUntrusted.json) to the current directory using the default URLs to pull the CCADB report and certdata.txt

         $ ./certdataDiffCCADB

* Output three JSON files (matched.json, unmatchedTrusted.json, and unmatchedUntrusted.json) to /tmp using the default URLs
    
        $ ./certdataDiffCCADB -o /tmp

* Output three JSON files (matched.json, unmatchedTrusted.json, and unmatchedUntrusted.json) to the current directory using the default CCADB URL and a local copy of certdata.txt
  
        $ ./certdataDiffCCADB -cd ~/Downloads/certdata.txt

* Output three JSON files (matched.json, unmatchedTrusted.json, and unmatchedUntrusted.json) to the current directory using the default certdata.txt URL and a local copy of a CCADB report.
  
        $ ./certdataDiffCCADB -cd ~/Downloads/IncludedCACertificateReportPEMCSV.csv

* Output three JSON files (matched.json, unmatchedTrusted.json, and unmatchedUntrusted.json) to the current directory using the default CCADB URL and a different remote URL for certdata.txt
        
        $ ./certdataDiffCCADB -cdurl https://some.other.domain/raw/certdata.txt

* Output three JSON files (matched.json, unmatchedTrusted.json, and unmatchedUntrusted.json) to the current directory using the default certdata.txt URL and a local copy of a CCADB report.
    
        $ ./certdataDiffCCADB -ccadburl https://some.other.domain/raw/ncludedCACertificateReportPEMCSV.csv

* Start the tool in `serve` mode.

        $ PORT=8080 ./certdataDiffCCADB --serve
