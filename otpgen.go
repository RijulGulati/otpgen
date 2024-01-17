// Package otpgen implements functions to generate TOTP/HOTP codes.
package otpgen

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

// TOTP represents Time-based OTP.
// See https://datatracker.ietf.org/doc/html/rfc6238
type TOTP struct {
	Secret    string // Secret key (required)
	Digits    int    // OTP digit count (default: 6)
	// SHA1 is accepted in OTP Algorithm, but it would be better to use more secure algorithms as the default
	Algorithm string // OTP Algorithm ("SHA1" or "SHA256" or "SHA512") (default: SHA256)
	Period    int64  // Period for which OTP is valid (seconds) (default: 30)
	UnixTime  int64  // (Optional) Unix Timestamp (default: Current unix timestamp)
}

// HOTP represents HMAC-Based One-Time Password Algorithm
// See https://datatracker.ietf.org/doc/html/rfc4226
type HOTP struct {
	Secret  string // Secret key (required)
	Digits  int    //OTP digit count (default: 6)
	Counter int64  // Counter value (default: 0)
}

// Generate TOTP code and returns OTP as string and any error encountered.
func (totp *TOTP) Generate() (string, error) {
	var T0 int64 = 0
	var currentUnixTime int64

	if totp.Secret == "" {
		return "", fmt.Errorf("no secret key provided")
	}

	if totp.Digits == 0 {
		totp.Digits = 6
	}

	if totp.Algorithm == "" {
		totp.Algorithm = "SHA256"
	}

	if totp.Period == 0 {
		totp.Period = 30
	}

	if totp.UnixTime != 0 {
		currentUnixTime = totp.UnixTime
	} else {
		currentUnixTime = time.Now().Unix() - T0
	}

	currentUnixTime /= totp.Period

	return generateOTP(totp.Secret, currentUnixTime, totp.Digits, totp.Algorithm)
}

// Generate HOTP code and returns OTP as string and any error encountered.
func (hotp *HOTP) Generate() (string, error) {

	if hotp.Secret == "" {
		return "", fmt.Errorf("no secret key provided")
	}

	if hotp.Digits == 0 {
		hotp.Digits = 6
	}

	return generateOTP(hotp.Secret, hotp.Counter, hotp.Digits, "SHA1")
}

// The main generate function that generates TOTP/HOTP code.
func generateOTP(base32Key string, counter int64, digits int, algo string) (string, error) {
	var hmacinit hash.Hash
	counterbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterbytes, uint64(counter))    //convert counter to byte array
	secretKey, err := base32.StdEncoding.DecodeString(base32Key) //decode base32 secret to byte array

	if err != nil {
		return "", fmt.Errorf("bad secret key")
	}

	switch strings.ToUpper(algo) {
	case "SHA1":
		{
			hmacinit = hmac.New(sha1.New, secretKey)
		}

	case "SHA256":
		{
			hmacinit = hmac.New(sha256.New, secretKey)
		}

	case "SHA512":
		{
			hmacinit = hmac.New(sha512.New, secretKey)
		}

	default:
		{
			return "", fmt.Errorf("invalid algorithm. Please use any one of SHA1/SHA256/SHA512")
		}
	}

	_, err = hmacinit.Write(counterbytes)
	if err != nil {
		return "", fmt.Errorf("unable to compute HMAC")
	}
	hash := hmacinit.Sum(nil)
	offset := hash[len(hash)-1] & 0xF
	hash = hash[offset : offset+4]

	hash[0] = hash[0] & 0x7F
	decimal := binary.BigEndian.Uint32(hash)
	otp := decimal % uint32(math.Pow10(digits))
	result := strconv.Itoa(int(otp))
	for len(result) != digits {
		result = "0" + result
	}
	return result, nil
}
