package sigauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		Code:    0,
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
		res.Data = 1
		w.Write([]byte(res.resJsonString()))
	}
}

// 起一个测试 server
func newTestServer(op SigAuthHandlerOption) *httptest.Server {
	op.SecretFinder = finderForTest
	timeChecker := op.TimeChecker
	// 没有指定的话，就走默认的时间检查器
	if timeChecker == nil {
		timeChecker = DefaultTimeChecker
	}
	sigAuthResolver := NewSigAuthResolver(op.AuthScheme, op.SecretFinder, timeChecker)
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

	t.Run("InvalidAuth", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus", nil)
		testRequest(t, r, `{"Code":400,"Message":"invalid Authorization","Data":null}`)
	})

	t.Run("InvalidAuthVersion", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus", nil)
		r.Header.Set(HttpHeaderAuthorization, fmt.Sprintf("%s Key=%s, Sign=sign, Timestamp=1, Version=-1", DefaultAuthScheme, _key))

		testRequest(t, r, `{"Code":400,"Message":"unsupported signature version","Data":null}`)
	})
	t.Run("UnknownKey", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus", nil)
		r.Header.Set(HttpHeaderAuthorization, fmt.Sprintf("%s Key=unknown, Sign=sign, Timestamp=1", DefaultAuthScheme))

		testRequest(t, r, `{"Code":400,"Message":"unknown key","Data":null}`)
	})
	t.Run("NoContentType", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodPost, s.URL+"?Plus", nil)
		r.Header.Set(HttpHeaderAuthorization, fmt.Sprintf("%s Key=%s, Sign=sign, Timestamp=1", DefaultAuthScheme, _key))

		testRequest(t, r, `{"Code":400,"Message":"missing Content-Type","Data":null}`)
	})
	t.Run("UnsupportedContentType", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodPost, s.URL+"?Plus", strings.NewReader("{}"))
		r.Header.Set(HttpHeaderAuthorization, fmt.Sprintf("%s Key=%s, Sign=sign, Timestamp=1", DefaultAuthScheme, _key))
		r.Header.Set(HttpHeaderContentType, "Invalid-Content-Type")

		testRequest(t, r, `{"Code":400,"Message":"unsupported Content-Type","Data":null}`)
	})
	t.Run("InvalidForm", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodPost, s.URL+"?Plus", strings.NewReader(";=;"))
		r.Header.Set(HttpHeaderAuthorization, fmt.Sprintf("%s Key=%s, Sign=sign, Timestamp=1", DefaultAuthScheme, _key))
		r.Header.Set(HttpHeaderContentType, ContentTypeForm)

		testRequest(t, r, `{"Code":400,"Message":"invalid request body","Data":null}`)
	})
	t.Run("BadSign", func(t *testing.T) {
		auth := BuildAuthorizationHeader(Authorization{
			Key:       _key,
			Sign:      "bad",
			Timestamp: _timestamp,
		})

		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus&x=1", nil)
		r.Header.Set(HttpHeaderAuthorization, auth)

		testRequest(t, r, `{"Code":400,"Message":"signature mismatch, want b7843d37ae086202d5f3e44b49b1b20ebcaf9a668347e839602a0d41156bb68d, got bad","Data":null}`)
	})
}

// 测试时间戳校验。
func TestSlimAuthApiHandler_timeChecker(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		s := newTestServer(SigAuthHandlerOption{}) // 自动使用 DefaultTimeChecker 。

		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus&x=1", nil)
		signResult := AppendSign(r, _key, _secret, "", time.Now().Unix())
		require.Equal(t, SignResultType_OK, signResult.Type)

		testRequest(t, r, `{"Code":0,"Message":"","Data":1}`)
	})
}
