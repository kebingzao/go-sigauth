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
		sigAuthResolver.VerifySignature(r)
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
func TestSigAuthApiHandler_timeChecker(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		s := newTestServer(SigAuthHandlerOption{}) // 自动使用 DefaultTimeChecker 。

		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus&x=1", nil)
		signResult := AppendSign(r, _key, _secret, "", time.Now().Unix())
		require.Equal(t, SignResultType_OK, signResult.Type)

		testRequest(t, r, `{"Code":0,"Message":"","Data":1}`)
	})
	t.Run("TimestampError", func(t *testing.T) {
		s := newTestServer(SigAuthHandlerOption{
			TimeChecker: DefaultTimeChecker,
		})
		// 默认误差在 300s， 这边设置为 1000，那就要报错
		timestamp := time.Now().Unix() + 1000

		r, _ := http.NewRequest(http.MethodGet, s.URL+"?Plus&x=1", nil)
		signResult := AppendSign(r, _key, _secret, "", timestamp)
		require.Equal(t, SignResultType_OK, signResult.Type)

		testRequest(t, r, `{"Code":400,"Message":"timestamp error","Data":null}`)
	})
}

func TestSigAuthHandler_ok(t *testing.T) {
	s := newTestServer(SigAuthHandlerOption{
		TimeChecker: NoTimeChecker,
	})

	t.Run("PlusViaForm", func(t *testing.T) {
		/*
			data to sign:
				1661934251
				POST
				/
				aPlus.c
				2211
				END
		*/

		auth := BuildAuthorizationHeader(Authorization{
			Key:       _key,
			Sign:      "1898c8c7fcbac3f72a7bd9378b747613b14b8d2c27c12c7f0a8d3402ac485105",
			Timestamp: _timestamp,
		})

		r, _ := http.NewRequest(http.MethodPost, s.URL+"?Plus&cc=c&AA=a&bb=.", strings.NewReader("x=11&Y=22"))
		r.Header.Set(HttpHeaderContentType, ContentTypeForm)
		r.Header.Set(HttpHeaderAuthorization, auth)

		testRequest(t, r, `{"Code":0,"Message":"","Data":1}`)
	})

	t.Run("PlusViaJson", func(t *testing.T) {
		/*
			data to sign:
				1661934251
				POST
				/
				Plus
				{"x":"1","Y":-2}
				END
		*/

		auth := BuildAuthorizationHeader(Authorization{
			Key:       _key,
			Sign:      "173cf7d616b64a297777d65ebbd19a1c37097bfdf2e0d18273c162e274c0b762",
			Timestamp: _timestamp,
		})

		r, _ := http.NewRequest(http.MethodPost, s.URL+"?Plus", strings.NewReader(`{"x":"1","Y":-2}`))
		r.Header.Set(HttpHeaderContentType, ContentTypeJson)
		r.Header.Set(HttpHeaderAuthorization, auth)

		testRequest(t, r, `{"Code":0,"Message":"","Data":1}`)
	})
	t.Run("GetKeyViaAuthInQuery", func(t *testing.T) {
		/*
			data to sign:
				1661934251
				POST
				/
				GetKey
				{}
				END
		*/

		auth := BuildAuthorizationHeader(Authorization{
			Key:       _key,
			Sign:      "3edb49ae24a03a730303745b9a1643726bbc2df6edf6da934e5ac425d3433991",
			Timestamp: _timestamp,
		})

		uri := s.URL + "?GetKey&~auth=" + url.QueryEscape(auth)
		r, _ := http.NewRequest(http.MethodPost, uri, strings.NewReader(`{}`))
		r.Header.Set(HttpHeaderContentType, ContentTypeJson)

		testRequest(t, r, `{"Code":0,"Message":"","Data":1}`)
	})
}

func TestSigAuthApiHandler_customScheme(t *testing.T) {
	const scheme = "CUSTOM-SCHEME"

	s := newTestServer(SigAuthHandlerOption{
		AuthScheme:  scheme,
		TimeChecker: NoTimeChecker,
	})

	t.Run("PlusViaForm", func(t *testing.T) {
		/*
			data to sign:
				1661934251
				POST
				/
				aPlus1122
				bc
				END
		*/

		auth := BuildAuthorizationHeader(Authorization{
			AuthScheme: scheme,
			Key:        _key,
			Sign:       "8f1adc3b9109a1808c4e1be6fb61fb5a0d93188e5a26a755ec346c30c04177c0",
			Timestamp:  _timestamp,
		})

		r, _ := http.NewRequest(http.MethodPost, s.URL+"?Plus&x=11&AA=a&y=22", strings.NewReader("c=c&b=b"))
		r.Header.Set(HttpHeaderContentType, ContentTypeForm)
		r.Header.Set(HttpHeaderAuthorization, auth)

		testRequest(t, r, `{"Code":0,"Message":"","Data":1}`)
	})
}
