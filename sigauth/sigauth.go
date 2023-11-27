package sigauth

const (
	// ContentTypeNone 未指定类型。
	ContentTypeNone = ""

	// ContentTypeJson 对应 Content-Type: application/json 的值。
	ContentTypeJson = "application/json"

	// ContentTypeBinary 对应 Content-Type: application/octet-stream 的值。
	ContentTypeBinary = "application/octet-stream"

	// ContentTypeJavascript 对应 Content-Type: text/javascript 的值。
	ContentTypeJavascript = "text/javascript"

	// ContentTypePlainText 对应 Content-Type: text/javascript 的值。
	ContentTypePlainText = "text/plain"

	// ContentTypeForm 对应 Content-Type: application/x-www-form-urlencoded 的值。
	ContentTypeForm = "application/x-www-form-urlencoded"

	// ContentTypeMultipartForm 对应 Content-Type: multipart/form-data 的值。
	ContentTypeMultipartForm = "multipart/form-data"
)

const (
	// HttpHeaderContentType 对应 HTTP 头中的 Content-Type 字段。
	HttpHeaderContentType = "Content-Type"

	// HttpHeaderContentDisposition 对应 HTTP 头中的 Content-Disposition 字段。
	HttpHeaderContentDisposition = "Content-Disposition"
)

const (
	// 默认的签名算法版本，当 Authorization 头没有写 Version 字段时，默认为此版本。
	DefaultSignVersion = 1

	// SlimAuth 协议在 HTTP Authorization 头的 <scheme> 部分，固定值。
	DefaultAuthScheme = "SIG-AUTH"

	// HTTP 协议的 Authorization 头。
	HttpHeaderAuthorization = "Authorization"

	// URL 上的元参数。当没有 Authorization 头时，也可以通过此参数获取 Authorization 值。
	// 优先级低于 Authorization 头。
	_metaParamAuth = "~auth"
)

// SecretFinderFunc 用于获取绑定到指定 accessKey 的 secret 。
// 若给定的 accessKey 没有绑定，返回空字符串。
// 若获取过程出错，直接 panic ，其错误处理方式与普通的 API 方法一致。
type SecretFinderFunc func(accessKey string) string

// SigAuthHandlerOption 用于初始化 。
type SigAuthHandlerOption struct {
	// 指定 HTTP Authorization 头的 scheme 部分的值。
	// 若为空，则自动使用默认值 [DefaultAuthScheme] 。
	AuthScheme string

	// 用于查找签名所需的 secret 。必须提供。
	SecretFinder SecretFinderFunc

	// 用于校验签名信息中携带的时间戳的有效性。
	// 若为 nil ，将自动使用 [DefaultTimeChecker] ；若不需要校验，可给定 [NoTimeChecker] 。
	TimeChecker TimeCheckerFunc
}

// NewSigAuthHandler 创建 SlimAuth 协议的 [webapi.ApiHandler] 。
func NewSigAuthHandler(op SigAuthHandlerOption) *sigAuthResolver {
	timeChecker := op.TimeChecker
	if timeChecker == nil {
		timeChecker = DefaultTimeChecker
	}
	return NewSigAuthResolver(op.AuthScheme, op.SecretFinder, timeChecker)
}
