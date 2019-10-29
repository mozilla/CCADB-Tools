use std::iter::Rev;

pub struct Revocation {
    pub issuer: String,
    pub serial: String
}

impl Revocation {

    pub fn to_cert_storage(&self) -> Vec<u8> {
        let i = base64::decode(&self.issuer).unwrap();
        let s = base64::decode(&self.serial).unwrap();
        vec![vec![b'i', b's'], i, s].concat()
    }
}


const RecordsPathPrefix: &str = "/v1/buckets/";
const bucket: &str = "security-state";
const RecordsPathSuffix: &str = "/collections/onecrl/records";

const ProductionPrefix: &str = "https://firefox.settings.services.mozilla.com";
const StagePrefix: &str = "https://settings.stage.mozaws.net";

//const prod: &str = ProductionPrefix + RecordsPathPrefix + bucket + RecordsPathSuffix;

fn production() -> String {
    format!("{}{}{}{}", ProductionPrefix, RecordsPathPrefix, bucket, RecordsPathSuffix)
}

fn staging() -> String {
    format!("{}{}{}{}", StagePrefix, RecordsPathPrefix, bucket, RecordsPathSuffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::cert_storage;

    const mozi: &str = "ME0xCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIgU2VjdXJlIFNlcnZlciBDQQ==";
    const mozs: &str = "DJduPkI49CDWPd+G7+u6kA==";
//    const p: &str = r#"C:\Users\Christopher Henderso\AppData\Roaming\Mozilla\Firefox\Profiles\b1e6quep.default-nightly\security_state\data.mdb"#;
    const p: &str = r#"H:\CCADB-Tools\oneCRL2CertStorage\data.mdb"#;
    #[test]
    fn local() {
        let r = Revocation{issuer: mozi.to_string(), serial: mozs.to_string()};
        let path = PathBuf::from(p);
        let mut pp = PathBuf::new();
        pp.push(r#"C:\"#);
        pp.push("Users");
        pp.push("Christopher Henderso");
        pp.push("AppData");
        pp.push("Roaming");
        pp.push("Mozilla");
        pp.push("Firefox");
        pp.push("Profiles");
        pp.push("b1e6quep.default-nightly");
        pp.push("security_state");
//        pp.push("CCADB-Tools");
//        pp.push("oneCRL2CertStorage");
////        pp.push("data.mdb");
        println!("{}", pp.exists());
        cert_storage::write(pp, r).unwrap();
    }
}

//const ProductionPrefix string = "https://firefox.settings.services.mozilla.com"
//const StagePrefix string = "https://settings.stage.mozaws.net"
//const RecordsPathPrefix string = "/v1/buckets/"
//const RecordsPathSuffix string = "/collections/onecrl/records"
//
//const PREFIX_BUGZILLA_PROD string = "https://bugzilla.mozilla.org"
//const PREFIX_BUGZILLA_STAGE string = "https://bugzilla.allizom.org"
//
//type OneCRLConfig struct {
//	oneCRLConfig       string
//	oneCRLEnvString    string `mapstructure:"onecrlenv"`
//	oneCRLBucketString string `mapstructure:"onecrlbucket"`
//	OneCRLVerbose      string `mapstructure:"onecrlverbose"`
//	BugzillaBase       string `mapstructure:"bugzilla"`
//	BugzillaAPIKey     string `mapstructure:"bzapikey"`
//	BugzillaReviewers  string `mapstructure:"reviewers"`
//	BugzillaBlockee    string `mapstructure:"blockee"`
//	BugDescription     string `mapstructure:"bugdescription"`
//	Preview            string `mapstructure:"preview"`
//	EnforceCRLChecks   string `mapstructure:"enforcecrlchecks"`
//	KintoUser          string `mapstructure:"kintouser"`
//	KintoPassword      string `mapstructure:"kintopass"`
//	KintoToken         string `mapstructure:"kintotoken"`
//	KintoCollectionURL string `mapstructure:"collectionurl"`
//	SkipBugzilla       bool   // Must be set by CLI flags
//	AdditionalConfig   map[string]string
//}
//
//// GetRecordURLForEnv returns the the URL (as a string) for a given OneCRL Environment ("stage" or "production")
//func (config OneCRLConfig) GetRecordURLForEnv(environment string) (error, string) {
//	var RecordsPath string = RecordsPathPrefix + config.oneCRLBucketString + RecordsPathSuffix
//
//	if environment == "stage" {
//		return nil, StagePrefix + RecordsPath
//	}
//	if environment == "production" {
//		return nil, ProductionPrefix + RecordsPath
//	}
//	return errors.New("valid onecrlenv values are \"stage\" and \"production\""), ""
//}
//
//func (config OneCRLConfig) GetRecordURL() (error, string) {
//	return config.GetRecordURLForEnv(config.oneCRLEnvString)
//}
