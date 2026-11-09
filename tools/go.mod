// Module tools pins the tools used by the tests. It is separate from the
// root module so that the tools' dependencies are not added to the module
// graph of the packages that import toutoumomoma.
module github.com/elastic/toutoumomoma/tools

go 1.26.9

// The golden values in toutoumomoma_golden_test.go are keyed on the Go and
// garble versions, so update them when this version changes.
tool mvdan.cc/garble

require (
	github.com/bluekeyes/go-gitdiff v0.9.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	mvdan.cc/garble v0.17.0 // indirect
)
