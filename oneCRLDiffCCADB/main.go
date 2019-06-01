package main // import "github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB"
import (
	"encoding/json"
	"fmt"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/ccadb"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/normalized"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/oneCRL"
	"net/http"
	"os"
)

func build() ([]*normalized.Normalized, error) {
	n := make([]*normalized.Normalized, 0)
	c, err := ccadb.Retrieve()
	if err != nil {
		return n, err
	}
	o, err := oneCRL.Retrieve()
	if err != nil {
		return n, err
	}
	n = normalized.Join(c, o)
	return n, nil
}

func inspect(norm []*normalized.Normalized) Return {
	ret := NewReturn()
	for _, n := range norm {
		if n.AddedAndPresent() {
			ret.AddedAndPresentInOneCRL = append(ret.AddedAndPresentInOneCRL, n)
		} else if n.ExpiredAndPresent() {
			ret.ExpiredAndPresentInOneCRL = append(ret.ExpiredAndPresentInOneCRL, n)
		} else if n.ReadyAndPresent() {
			ret.ReadyToAddAndPresentInOneCRL = append(ret.ReadyToAddAndPresentInOneCRL, n)
		} else if n.AbsentAndPresent() {
			ret.AbsentFromCCADBAndPresentInOneCRL = append(ret.AbsentFromCCADBAndPresentInOneCRL, n)
		} else if n.AddedAndAbsent() {
			ret.AddedAndAbsentFromOneCRL = append(ret.AddedAndAbsentFromOneCRL, n)
		} else if n.ExpiredAndAbsent() {
			ret.ExpiredAndAbsentFromOneCRL = append(ret.ExpiredAndAbsentFromOneCRL, n)
		} else if n.ReadyAndAbsent() {
			ret.ReadyToAddAndAbsentFromOneCRL = append(ret.ReadyToAddAndAbsentFromOneCRL, n)
		}
	}
	return ret
}

type Return struct {
	AddedAndPresentInOneCRL           []*normalized.Normalized
	ExpiredAndPresentInOneCRL         []*normalized.Normalized
	ReadyToAddAndPresentInOneCRL      []*normalized.Normalized
	AbsentFromCCADBAndPresentInOneCRL []*normalized.Normalized

	AddedAndAbsentFromOneCRL      []*normalized.Normalized
	ExpiredAndAbsentFromOneCRL    []*normalized.Normalized
	ReadyToAddAndAbsentFromOneCRL []*normalized.Normalized
}

func NewReturn() Return {
	return Return{
		make([]*normalized.Normalized, 0),
		make([]*normalized.Normalized, 0),
		make([]*normalized.Normalized, 0),
		make([]*normalized.Normalized, 0),
		make([]*normalized.Normalized, 0),
		make([]*normalized.Normalized, 0),
		make([]*normalized.Normalized, 0),
	}
}

func endpoint(w http.ResponseWriter, r *http.Request) {
	built, err := build()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	ret := inspect(built)
	j, err := json.MarshalIndent(ret, "", "  ")
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(200)
	w.Write(j)
}

func main() {
	http.HandleFunc("/", endpoint)
	var port string
	switch env := os.Getenv("PORT"); env {
	case "":
		port = ":8080"
	default:
		port = fmt.Sprintf(":%s", env)
	}
	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
	}
}
