# Fork of x509lint
This fork of https://github.com/kroeckx/x509lint adds a command-line option for selecting the certificate type, and this command-line option is relied on by capi/lib/lint/x509lint/x509lint.go#L80.  
Perhaps at some point this can be resolved so that this fork will not be needed. 
See https://github.com/kroeckx/x509lint/pull/33 for further context.

Another way to resolve this would be to update capi to use https://github.com/crtsh/go-x509lint library instead. That library is a Go wrapper for the latest version of kroeckx/x509lint, which embeds x509lint in the Go binary (using Cgo) instead of executing it in a separate process.  crtsh/go-x509lint's Check function supports the same sort of certificate type selection that was added in this fork.
