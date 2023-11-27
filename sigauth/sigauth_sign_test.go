package sigauth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 测试 auth 头部拼接逻辑
func TestBuildAuthorizationHeader(t *testing.T) {
	t.Run("HasVersion", func(t *testing.T) {
		res := BuildAuthorizationHeader(Authorization{
			Key:       "kkk",
			Sign:      "sss",
			Timestamp: 123,
			Version:   321,
		})
		assert.Equal(t, "SIG-AUTH Key=kkk, Sign=sss, Timestamp=123, Version=321", res)
	})

	t.Run("NoVersion", func(t *testing.T) {
		res := BuildAuthorizationHeader(Authorization{
			Key:       "kk",
			Sign:      "ss",
			Timestamp: 123,
		})
		assert.Equal(t, "SIG-AUTH Key=kk, Sign=ss, Timestamp=123", res)
	})

	t.Run("CustomScheme", func(t *testing.T) {
		res := BuildAuthorizationHeader(Authorization{
			AuthScheme: "CUSTOM",
			Key:        "kk",
			Sign:       "ss",
			Timestamp:  123,
		})
		assert.Equal(t, "CUSTOM Key=kk, Sign=ss, Timestamp=123", res)
	})
}

// 测试 http 请求 Authorization 头部解析
func TestParseAuthorizationHeader(t *testing.T) {
	do := func(authQuery string, header ...string) (Authorization, error) {
		uri := "http://temp.org"
		if authQuery != "" {
			uri += "?~auth=" + url.QueryEscape(authQuery)
		}

		u, _ := url.Parse(uri)
		r := &http.Request{
			URL:    u,
			Header: make(http.Header),
		}

		if len(header) > 0 {
			for _, v := range header {
				r.Header.Add(HttpHeaderAuthorization, v)
			}
		}

		return ParseAuthorizationHeader(r, "")
	}

	t.Run("NoHeader", func(t *testing.T) {
		_, err := do("")
		require.Error(t, err)
		require.Regexp(t, "missing", err.Error())
	})

	t.Run("TooManyHeaders", func(t *testing.T) {
		_, err := do("", "1", "2")
		require.Error(t, err)
		require.Regexp(t, "more than one", err.Error())
	})

	t.Run("NoScheme", func(t *testing.T) {
		_, err := do("", "gg")
		require.Error(t, err)
		require.Regexp(t, "scheme error", err.Error())
	})

	t.Run("WrongScheme", func(t *testing.T) {
		_, err := do("", "Bad Key=1")
		require.Error(t, err)
		require.Regexp(t, "scheme match error", err.Error())
	})

	t.Run("BadVersion", func(t *testing.T) {
		_, err := do("", "SIG-AUTH Version=abc")
		require.Error(t, err)
		require.Regexp(t, "version error", err.Error())
	})

	t.Run("BadTimestamp", func(t *testing.T) {
		_, err := do("SIG-AUTH Timestamp=abc")
		require.Error(t, err)
		require.Regexp(t, "timestamp error", err.Error())
	})

	t.Run("OK-FromHeader", func(t *testing.T) {
		auth, err := do("", "SIG-AUTH Key=kk, Sign=ss, Timestamp=1661843240, Version=123")
		require.NoError(t, err)

		assert.Equal(t, "kk", auth.Key)
		assert.Equal(t, "ss", auth.Sign)
		assert.Equal(t, int64(1661843240), auth.Timestamp)
		assert.Equal(t, 123, auth.Version)
	})

	t.Run("OK-DefaultVersion", func(t *testing.T) {
		auth, err := do("", "SIG-AUTH Key=kk")
		require.NoError(t, err)

		assert.Equal(t, "kk", auth.Key)
		assert.Equal(t, 1, auth.Version)
	})

	t.Run("OK-FromQuery", func(t *testing.T) {
		auth, err := do("SIG-AUTH Key=kk, Sign=ss, Timestamp=1661843240, Version=123")
		require.NoError(t, err)

		assert.Equal(t, "kk", auth.Key)
		assert.Equal(t, "ss", auth.Sign)
		assert.Equal(t, int64(1661843240), auth.Timestamp)
		assert.Equal(t, 123, auth.Version)
	})
}

// 测试自定义签名名称
func TestParseAuthorizationHeader_customScheme(t *testing.T) {
	r := &http.Request{
		Header: make(http.Header),
	}
	r.Header.Set(HttpHeaderAuthorization, "CUSTOM Key=kk, Sign=ss, Timestamp=1661843240")

	t.Run("OK", func(t *testing.T) {
		auth, err := ParseAuthorizationHeader(r, "CUSTOM")
		require.NoError(t, err)
		assert.Equal(t, "CUSTOM", auth.AuthScheme)
	})

	t.Run("Error", func(t *testing.T) {
		_, err := ParseAuthorizationHeader(r, "")
		require.Error(t, err)
		assert.Regexp(t, "Authorization scheme match error", err.Error())
	})
}

func TestHmacSha256(t *testing.T) {
	got := HmacSha256([]byte(_secret), []byte("plain to hash"))
	assert.Equal(t, "f7138e89b7b6167ee938f0ba9eef0cea4c7080e027bb84ab216acb264fc7d5a3", got)
}

// 测试签名算法
func Test_buildDataToSign(t *testing.T) {
	t.Run("EmptyPath", func(t *testing.T) {
		r := newRequest("",
			"",
			_requestTypeGet,
			"",
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_OK, typ)
		assert.Nil(t, err)

		want := "12345\nGET\n/\n\nEND"
		assert.Equal(t, want, string(data))
	})

	t.Run("SingleSlashPath", func(t *testing.T) {
		r := newRequest("",
			"/",
			_requestTypeGet,
			"",
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_OK, typ)
		assert.Nil(t, err)

		want := "12345\nGET\n/\n\nEND"
		assert.Equal(t, want, string(data))
	})

	t.Run("Get", func(t *testing.T) {
		r := newRequest("",
			"/path/sub/?bb=22&D&aa=11&cc=&D&E=5&bb=44&~auth=x",
			_requestTypeGet,
			"",
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_OK, typ)
		assert.Nil(t, err)

		// ASCII 顺序下大写字母排在小写前面。
		// 同名参数顺序需得到保证。
		want := "12345\nGET\n/path/sub/\nDD5112244cc\nEND"
		assert.Equal(t, want, string(data))
	})

	t.Run("Form", func(t *testing.T) {
		r := newRequest("",
			"/p?x=&y=",
			_requestTypeForm,
			"bb=22&aa=11&dd&&cc=33",
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_OK, typ)
		assert.Nil(t, err)

		want := "12345\nPOST\n/p\nxy\n112233dd\nEND"
		assert.Equal(t, want, string(data))
	})

	t.Run("Json", func(t *testing.T) {
		r := newRequest("",
			"/p?x=x&y=y",
			_requestTypeJson,
			`{"Data":"value"}`,
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_OK, typ)
		assert.Nil(t, err)

		want := "12345\nPOST\n/p\nxy\n{\"Data\":\"value\"}\nEND"
		assert.Equal(t, want, string(data))
	})

	t.Run("ErrorBadForm", func(t *testing.T) {
		r := newRequest("",
			"",
			_requestTypeForm,
			"",
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_InvalidRequestBody, typ)
		assert.Nil(t, data)
		require.Error(t, err)
	})

	t.Run("ErrorNilJsonBody", func(t *testing.T) {
		r := newRequest("",
			"",
			_requestTypeJson,
			"",
		)
		data, typ, err := buildDataToSign(r, false, 12345)
		assert.Equal(t, SignResultType_InvalidRequestBody, typ)
		assert.Nil(t, data)
		require.Error(t, err)
		require.Regexp(t, "missing body", err.Error())
	})
}

// 测试完整签名
func TestAppendSign(t *testing.T) {
	r := newRequest("", "/", _requestTypeGet, "")
	signResult := AppendSign(r, _key, _secret, "SCH", _timestamp)
	require.Equal(t, SignResultType_OK, signResult.Type)

	auth, ok := r.Header[HttpHeaderAuthorization]
	require.True(t, ok)

	want := "SCH Key=testKey, Sign=7583e11e7be21d4b3aa178e8011f18c8d84633403cb0ef62f020ebe121bdc065, Timestamp=1661934251, Version=1"
	assert.Equal(t, want, auth[0])
}

func TestSign(t *testing.T) {
	t.Run("OK-Get", func(t *testing.T) {
		r := newRequest("", "/", _requestTypeGet, "")
		signResult := Sign(r, false, _secret, _timestamp)
		assert.Equal(t, SignResultType_OK, signResult.Type)
		assert.Equal(t, "7583e11e7be21d4b3aa178e8011f18c8d84633403cb0ef62f020ebe121bdc065", signResult.Sign)
	})

	t.Run("OK-Form", func(t *testing.T) {
		r := newRequest("",
			"/path?a=1&b=2",
			_requestTypeForm,
			`x=x&y=y`,
		)
		signResult := Sign(r, false, _secret, _timestamp)
		assert.Equal(t, SignResultType_OK, signResult.Type)
		assert.Equal(t, "0942cde16e2be07c86a13f41c645120609fbab50bb2f6b49c8a536dcfa1eae41", signResult.Sign)
	})

	t.Run("OK-Json", func(t *testing.T) {
		r := newRequest("",
			"/path?a=1&b=2",
			_requestTypeJson,
			`{}`,
		)
		signResult := Sign(r, false, _secret, _timestamp)
		assert.Equal(t, SignResultType_OK, signResult.Type)
		assert.Equal(t, "3e090a4cccdae1e40ae67b2fd137f8ca99cf5e2a63a4e7587d88c247a24182e0", signResult.Sign)
	})

	t.Run("OK-EmptyParamValue", func(t *testing.T) {
		r := newRequest("",
			"/path?a&b&c",
			_requestTypeForm,
			"x=&y=&z=",
		)
		signResult := Sign(r, false, _secret, _timestamp)
		assert.Equal(t, SignResultType_OK, signResult.Type)
		assert.Equal(t, "c26dfba4cb6b2bfec76dbd0f0a46b8cc779c2636b7136b100f3ecba7e6a488c8", signResult.Sign)
	})
}
