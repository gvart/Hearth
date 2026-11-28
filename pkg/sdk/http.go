// SPDX-License-Identifier: Apache-2.0

package sdk

// HTTPRequest is an HTTP request a plugin makes with HTTP.
type HTTPRequest struct {
	// Method is GET (the default when empty), HEAD, POST, PUT, PATCH or
	// DELETE.
	Method string `json:"method,omitempty"`
	// URL is an http or https URL.
	URL    string            `json:"url"`
	Header map[string]string `json:"header,omitempty"`
	// Body is up to 64 KiB.
	Body []byte `json:"body,omitempty"`
}

// HTTPResponse is the answer to an HTTPRequest. Redirects are not
// followed: a redirect is a response like any other.
type HTTPResponse struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header"`
	// Body is up to 1 MiB: a larger one is an error.
	Body []byte `json:"body"`
}

// HTTP makes an HTTP request. In a WASM plugin it is the hub's http host
// function: the manifest must grant it for the request's host and port
// (host.http.allow), and the hub decides and audits every call. In an exec
// plugin it is a plain request, with the same limits.
func HTTP(req HTTPRequest) (HTTPResponse, error) { return doHTTP(req) }
