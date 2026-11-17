// Marker module: keeps web/ (including node_modules, some of which ship Go
// sources) out of the github.com/gvart/hearth module, so `go test ./...`,
// `go build ./...` and golangci-lint never descend into npm packages.
module github.com/gvart/hearth/web

go 1.26.0
