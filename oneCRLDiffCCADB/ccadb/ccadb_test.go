package ccadb

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/oneCRL"
)

func TestRet(t *testing.T) {
	retrieve()
}

func TestCmp(t *testing.T) {
	one, err := oneCRL.Retrieve()
	if err != nil {
		panic(err)
	}
	records := retrieve()
	present := 0
	for _, o := range one.Data {
		one_s, err := base64.StdEncoding.DecodeString(o.SerialNumber)
		if err != nil {
			panic(err)
		}
		for _, c := range records {
			ccadb_s, err := hex.DecodeString(c[schema["Certificate Serial Number"]])
			if err != nil {
				fmt.Println(c[schema["Certificate Serial Number"]], err)
				continue
			}
			if reflect.DeepEqual(one_s, ccadb_s) {
				present += 1
				break
			}
		}
	}
	fmt.Println(present)
	fmt.Println(len(one.Data))
	fmt.Println(len(records))
}

func TestBS(t *testing.T) {
	fmt.Println([]byte("‎0727B60A"))
	fmt.Println([]byte("0727B60A"))
	var b []byte
	fmt.Println(hex.Decode(b, []byte("‎0727B60A")))
	//fmt.Println(hex.DecodeString("‎0727B60A"))
}
