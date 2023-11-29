package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sigauth/sigauth"
)

var (
	//go:embed static/client.html
	_clientDemoPage string
	// 设置各个组的 key 和 secret
	SigAuthKeySecret = [][]string{
		{"testkey1", "secret1"},
		{"testkey2", "secret2"},
	}
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

func initServer() {
	serverMux := http.NewServeMux()
	// 普通没有校验的请求
	serverMux.HandleFunc("/hello", helloHandler)
	// 需要 sigAuth 的请求
	serverMux.HandleFunc("/sigauth/hello", corsAuthHandler(sigAuthHandler(helloHandler)))
	// 渲染 html demo 页面
	serverMux.HandleFunc("/demo/", htmlDemoHandler)
	// 开启 HTTP 服务。
	server := &http.Server{
		Addr:    ":8012",
		Handler: serverMux,
	}
	fmt.Println("Http server listening on addr " + server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// 给前端设置 cors 跨域
func setCors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "origin, content-type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// 针对 hello 的请求
func helloHandler(w http.ResponseWriter, r *http.Request) {
	res := NewRes()
	urlValues := r.URL.Query()
	msg := urlValues.Get("msg")
	res.Message = msg
	if r.Method == http.MethodPost {
		respBytes, _ := io.ReadAll(r.Body)
		res.Data = string(respBytes)
	}
	w.Write([]byte(res.resJsonString()))
}

// 针对 html demo 页面的渲染
func htmlDemoHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(_clientDemoPage))
}

// 验签
func verifySignature(r *http.Request) {
	// 设置获取 secret 的 filter
	secretFinder := func(accessKey string) string {
		for _, keySec := range SigAuthKeySecret {
			if accessKey == keySec[0] {
				return keySec[1]
			}
		}
		return ""
	}
	op := sigauth.SigAuthHandlerOption{
		SecretFinder: secretFinder,
		// TimeChecker:  sigauth.NoTimeChecker,
		TimeChecker: sigauth.DefaultTimeChecker,
	}
	sigAuthResolver := sigauth.NewSigAuthResolver(op.AuthScheme, op.SecretFinder, op.TimeChecker)
	sigAuthResolver.VerifySignature(r)
}

// cors 验证中间件, 便于前端 demo 页面可以解耦部署在其他的 web server
func corsAuthHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCors(w, r)
		// 过滤掉 options 方法
		if r.Method == "OPTIONS" {
			w.Write([]byte("ok"))
			return
		}
		handler(w, r)
	}
}

// sigauth 验证中间件
func sigAuthHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := NewRes()
		// 捕获错误
		defer func() {
			if err := recover(); err != nil {
				res.Code = 400
				res.Message = err.(string)
				fmt.Printf("%s => %s\n", r.URL, res.Message)
				w.Write([]byte(res.resJsonString()))
			}
		}()
		// 进行签名验证
		verifySignature(r)
		handler(w, r)
	}
}

func main() {
	initServer()
}
