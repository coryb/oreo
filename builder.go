package oreo

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type reqBuilder struct {
	request *http.Request
}

func ReqBuilder(u *url.URL) *reqBuilder {
	return &reqBuilder{
		request: &http.Request{
			Method:     "GET",
			URL:        u,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       nil,
			Host:       u.Host,
		},
	}
}

func (b *reqBuilder) WithHeader(name, value string) *reqBuilder {
	b.request.Header.Add(name, value)
	return b
}

func (b *reqBuilder) WithContentType(value string) *reqBuilder {
	b.request.Header.Add("Content-Type", value)
	return b
}

func (b *reqBuilder) WithUserAgent(value string) *reqBuilder {
	b.request.Header.Add("User-Agent", value)
	return b
}

func (b *reqBuilder) WithMethod(method string) *reqBuilder {
	b.request.Method = method
	return b
}

func (b *reqBuilder) WithJSON(data string) *reqBuilder {
	contentType := "application/json"
	return b.WithContentType(contentType).WithHeader("Accept", contentType).WithBody(strings.NewReader(data))
}

func (b *reqBuilder) WithPostForm(data url.Values) *reqBuilder {
	return b.WithContentType("application/x-www-form-urlencoded").WithBody(strings.NewReader(data.Encode()))
}

func (b *reqBuilder) WithBody(body io.Reader) *reqBuilder {
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	b.request.Body = rc
	return b
}

func (b *reqBuilder) WithAuth(username, password string) *reqBuilder {
	b.request.SetBasicAuth(username, password)
	return b
}

func (b *reqBuilder) Build() *http.Request {
	return b.request
}
