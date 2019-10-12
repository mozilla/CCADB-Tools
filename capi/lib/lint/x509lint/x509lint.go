package x509lint

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

type X509Lint struct {
	Errors   []string
	Warnings []string
	Info     []string
	CmdError *string
}

func LintChain(certificates []*x509.Certificate) []X509Lint {
	results := make([]X509Lint, len(certificates))
	for _, cert := range certificates {
		results = append(results, Lint(cert))
	}
	return results
}

func Lint(certificate *x509.Certificate) X509Lint {
	result := NewX509Lint()
	f, err := ioutil.TempFile("", "x509lint")
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil {
			log.Println(err)
		}
	}()
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	err = f.Close()
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	cmd := exec.Command("x509lint", f.Name())
	stdout := bytes.NewBuffer([]byte{})
	stderr := bytes.NewBuffer([]byte{})
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	//stdout, err := cmd.StdoutPipe()
	//if err != nil {
	//	errStr := err.Error()
	//	result.CmdError = &errStr
	//	return result
	//}
	//defer stdout.Close()
	//stderr, err := cmd.StderrPipe()
	//if err != nil {
	//	errStr := err.Error()
	//	result.CmdError = &errStr
	//	return result
	//}
	//defer stderr.Close()
	err = cmd.Run()
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	output, err := ioutil.ReadAll(stdout)
	if err != nil {
		log.Println("closing stdout")
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	errors, err := ioutil.ReadAll(stderr)
	if err != nil {
		log.Println("closing stderr")
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	if string(errors) != "" {
		errStr := string(errors)
		result.CmdError = &errStr
		return result
	}
	parseOutput(output, &result)
	return result
}

func NewX509Lint() X509Lint {
	return X509Lint{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
		Info:     make([]string, 0),
		CmdError: nil,
	}
}

func parseOutput(output []byte, result *X509Lint) {
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("E: ")) {
			result.Errors = append(result.Errors, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("W: ")) {
			result.Warnings = append(result.Warnings, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("I: ")) {
			result.Info = append(result.Info, string(line[3:]))
		}
	}
}
