package sigauth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	_requestTypeGet  = 0
	_requestTypeForm = 1
	_requestTypeJson = 2

	// 没有时间戳校验时，固定用此时间戳测试，以便获得稳定可断言的 hash 。
	_timestamp = 1661934251

	// 测试时表示合法的 access-key 。
	_key = "testKey"

	// 当 access-key 为 testKey 时，返回这个密钥。
	_secret = "testSecret"
)

// baseUrl 可留空。
func newRequest(baseUrl, pathAndQuery string, typ int, body string) *http.Request {
	if baseUrl == "" {
		baseUrl = "http://temp.org"
	}

	url, err := url.Parse(baseUrl + pathAndQuery)
	if err != nil {
		panic(err)
	}

	r := &http.Request{
		URL:    url,
		Header: make(http.Header),
	}

	if body != "" {
		r.Body = io.NopCloser(strings.NewReader(body))
	}

	switch typ {
	case _requestTypeGet:
		r.Method = http.MethodGet

	case _requestTypeForm:
		r.Method = http.MethodPost
		r.Header.Set(HttpHeaderContentType, ContentTypeForm)

	case _requestTypeJson:
		r.Method = http.MethodPost
		r.Header.Set(HttpHeaderContentType, ContentTypeJson)
	}

	return r
}
