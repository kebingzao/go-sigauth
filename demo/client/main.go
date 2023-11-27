package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sigauth/sigauth"
	"strings"
	"time"
)

const baseUrl = "http://localhost:8012"

var (
	// 设置各个组的 key 和 secret
	SigAuthKeySecret = [][]string{
		{"testkey1", "secret1"},
		{"testkey2", "secret2"},
	}
)

func sendRequest(r *http.Request) {
	client := new(http.Client)
	res, err := client.Do(r)
	if err != nil {
		fmt.Printf("sendRequest, err=%v", err)
		return
	}
	body, _ := io.ReadAll(res.Body)
	fmt.Printf("%s => %s\n", r.URL, string(body))
}

func setUrl(path, query string) (url string) {
	url = fmt.Sprintf("%s/%s", baseUrl, path)
	if query != "" {
		url = fmt.Sprintf("%s?%s", url, query)
	}
	return
}

// 设置签名
func setSign(r *http.Request, accessKey, secret string, timestamp int64) {
	signResult := sigauth.AppendSign(r, accessKey, secret, "", timestamp)
	if signResult.Type != sigauth.SignResultType_OK {
		fmt.Println("sign err:", signResult.Cause.Error())
	}
}

type SetSignFunc func(r *http.Request)

func tryRequest(method, url string, body io.Reader, auth string, setSignFunc SetSignFunc) {
	r, _ := http.NewRequest(method, url, body)
	if auth != "" {
		r.Header.Set(sigauth.HttpHeaderAuthorization, auth)
	}
	if setSignFunc != nil {
		setSignFunc(r)
	}
	sendRequest(r)
}

func main() {
	//========= 以下是 get 请求 =============
	// 请求普通的 hello
	tryRequest(http.MethodGet, setUrl("hello", "msg=123"), nil, "", nil)
	// 请求 sigauth 的 hello, 因为没有加 auth，所以会报这个 {"Code":400,"Message":"invalid Authorization","Data":null}
	tryRequest(http.MethodGet, setUrl("sigauth/hello", "msg=123"), nil, "", nil)
	// 有添加 auth 的, 但是 auth 不对的
	tryRequest(http.MethodGet, setUrl("sigauth/hello", "msg=12345"), nil, fmt.Sprintf("SIG-AUTH Key=testkey1, Sign=sign, Timestamp=%v", time.Now().Unix()), nil)
	// auth 是对的
	tryRequest(http.MethodGet, setUrl("sigauth/hello", "msg=123456"), nil, "", func(r *http.Request) {
		setSign(r, SigAuthKeySecret[0][0], SigAuthKeySecret[0][1], time.Now().Unix())
	})
	// ======== 以下是 post 请求==========
	// 普通请求
	tryRequest(http.MethodPost, setUrl("hello", "msg=123"), strings.NewReader("a=11&b=22"), "", nil)
	// 验证请求
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123"), strings.NewReader("a=11&b=22"), "", nil)
	// auth 是对的
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123456"), strings.NewReader("a=11&b=2222"), "", func(r *http.Request) {
		r.Header.Set(sigauth.HttpHeaderContentType, sigauth.ContentTypeForm)
		setSign(r, SigAuthKeySecret[0][0], SigAuthKeySecret[0][1], time.Now().Unix())
	})
	// post json, 但是并没有设置 content-type
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123456"), strings.NewReader(`{"x":"1","Y":2}`), "", func(r *http.Request) {
		setSign(r, SigAuthKeySecret[1][0], SigAuthKeySecret[1][1], time.Now().Unix())
	})
	// post json
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123456"), strings.NewReader(`{"x":"1","Y":2}`), "", func(r *http.Request) {
		r.Header.Set(sigauth.HttpHeaderContentType, sigauth.ContentTypeJson)
		setSign(r, SigAuthKeySecret[1][0], SigAuthKeySecret[1][1], time.Now().Unix())
	})
	// post json, 但是 content-type 不支持
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123456"), strings.NewReader(`{"x":"1","Y":2}`), "", func(r *http.Request) {
		r.Header.Set(sigauth.HttpHeaderContentType, sigauth.ContentTypeMultipartForm)
		setSign(r, SigAuthKeySecret[1][0], SigAuthKeySecret[1][1], time.Now().Unix())
	})
	// post json, 但是 时间戳过期
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123456"), strings.NewReader(`{"x":"1","Y":2}`), "", func(r *http.Request) {
		r.Header.Set(sigauth.HttpHeaderContentType, sigauth.ContentTypeJson)
		setSign(r, SigAuthKeySecret[1][0], SigAuthKeySecret[1][1], time.Now().Unix()-1000)
	})
	// post json, 但是找不到 key 对应是 secret
	tryRequest(http.MethodPost, setUrl("sigauth/hello", "msg=123456"), strings.NewReader(`{"x":"1","Y":2}`), "", func(r *http.Request) {
		r.Header.Set(sigauth.HttpHeaderContentType, sigauth.ContentTypeJson)
		setSign(r, "key", SigAuthKeySecret[1][1], time.Now().Unix())
	})
	// post json 将 auth 放到 参数 ~auth, 注意，如果要这个方式要成功的话， server 那边要将 timeCheck 关闭，不然 sign 会一直变
	// auth := sigauth.BuildAuthorizationHeader(sigauth.Authorization{
	// 	Key:       "testkey1",
	// 	Sign:      "fb954c9a49c0914c9c4d7af2fc4c0d0b20e7d6060ebd37dedb0b03edac138694",
	// 	Timestamp: 1661934251,
	// })
	auth := "SIG-AUTH Key=testkey1, Sign=fb954c9a49c0914c9c4d7af2fc4c0d0b20e7d6060ebd37dedb0b03edac138694, Timestamp=1661934251"
	tryRequest(http.MethodPost, setUrl("sigauth/hello", fmt.Sprintf("msg=123456&~auth=%s", url.QueryEscape(auth))), strings.NewReader(`{"x":"1","Y":2}`), "", func(r *http.Request) {
		r.Header.Set(sigauth.HttpHeaderContentType, sigauth.ContentTypeJson)
	})
}
