package utils

import "os"

var (
	ZEROSSL_KID  = os.Getenv("ZEROSSL_KID")
	ZEROSSL_HMAC = os.Getenv("ZEROSSL_HMAC")
)
