package sigauth

import (
	"fmt"
	"net/http"
)

// 解签对象
type sigAuthResolver struct {
	authScheme   string
	secretFinder SecretFinderFunc
	timeChecker  TimeCheckerFunc
}

// 初始化解签对象
func NewSigAuthResolver(authScheme string, secretFinder SecretFinderFunc, timeChecker TimeCheckerFunc) *sigAuthResolver {
	if secretFinder == nil {
		panic("secretFinder must be provided")
	}

	if timeChecker == nil {
		panic("timeChecker must be provided")
	}

	return &sigAuthResolver{
		authScheme:   authScheme,
		secretFinder: secretFinder,
		timeChecker:  timeChecker,
	}
}

func (x sigAuthResolver) verifySignature(r *http.Request) {
	auth, err := ParseAuthorizationHeader(r, x.authScheme)
	if err != nil {
		panic("invalid Authorization")
	}

	// 签名算法目前就一个版本，不允许出现其他值。
	if auth.Version != DefaultSignVersion {
		panic("unsupported signature version")
	}

	secret := x.secretFinder(auth.Key)
	if secret == "" {
		panic("unknown key")
	}

	// 后续走 SlimAPI 的 decode 过程，需要重读 body 。
	signResult := Sign(r, true, secret, auth.Timestamp)

	// 时间戳校验。
	timeCheckErr := x.timeChecker(auth.Timestamp)
	if timeCheckErr != nil {
		panic("timestamp error")
	}

	switch signResult.Type {
	case SignResultType_MissingContentType:
		panic("missing Content-Type")

	case SignResultType_UnsupportedContentType:
		panic("unsupported Content-Type")

	case SignResultType_InvalidRequestBody:
		panic("invalid request body")
	}

	if signResult.Sign != auth.Sign {
		panic(fmt.Sprintf("signature mismatch, want %s, got %s", signResult.Sign, auth.Sign))
	}
}
