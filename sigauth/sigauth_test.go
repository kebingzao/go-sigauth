package sigauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

// 服务端返回标准格式
type Res struct {
	Code    int
	Message string
	Data    interface{}
}

func NewRes() Res {
	res := Res{
		Code:    200,
		Message: "",
		Data:    nil,
	}
	return res
}

func (r *Res) resJsonString() (resJson string) {
	res, _ := json.Marshal(r)
	resJson = string(res)
	return
}

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

// 根据 key 或者对应的 secret
func finderForTest(accessKey string) string {
	switch accessKey {
	case _key:
		return _secret

	default:
		return ""
	}
}

// 创建监听事件，这边跑测试简单处理，真实业务上，应该是作为一个验证中间件，不应写在业务 handler 里面，至少还需再抽象一层
func CreateHandlerFunc(sigAuthResolver *sigAuthResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := NewRes()
		// 捕获错误
		defer func() {
			if err := recover(); err != nil {
				res.Code = 400
				res.Message = err.(string)
				w.Write([]byte(res.resJsonString()))
			}
		}()
		// 进行签名验证
		sigAuthResolver.verifySignature(r)
		// 在这边进行校验
		res.Message = "OK"
		w.Write([]byte(res.resJsonString()))
	}
}

// 起一个测试 server
func newTestServer(op SigAuthHandlerOption) *httptest.Server {
	op.SecretFinder = finderForTest
	sigAuthResolver := NewSigAuthHandler(op)
	handlerFunc := CreateHandlerFunc(sigAuthResolver)
	ts := httptest.NewServer(http.HandlerFunc(handlerFunc))
	return ts
}

func testRequest(t *testing.T, r *http.Request, want string) {
	client := new(http.Client)
	res, _ := client.Do(r)
	body, _ := io.ReadAll(res.Body)
	assert.Equal(t, want, string(body))
}

// 测试不包含时间戳校验的其他错误。
func TestSigAuthHandler_errors(t *testing.T) {
	s := newTestServer(SigAuthHandlerOption{
		TimeChecker: NoTimeChecker,
	})

	t.Run("NoMethod", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, s.URL, nil)
		testRequest(t, r, `{"Code":400,"Message":"invalid Authorization","Data":null}`)
	})
}
