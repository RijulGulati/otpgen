package otpgen

import (
	"encoding/base32"
	"testing"
)

type TOTPTest struct {
	TOTP
	Output string
}

type HOTPTest struct {
	HOTP
	Output string
}

func TestTOTP(t *testing.T) {

	testcases := []TOTPTest{
		{TOTP: TOTP{Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"},
		{TOTP: TOTP{Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"},
		{TOTP: TOTP{Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"},
		{TOTP: TOTP{Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"},
		{TOTP: TOTP{Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"},
		{TOTP: TOTP{Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"},
		{TOTP: TOTP{Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"},
		{TOTP: TOTP{Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"},
		{TOTP: TOTP{Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"},
		{TOTP: TOTP{Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"},
		{TOTP: TOTP{Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"},
		{TOTP: TOTP{Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"},
		{TOTP: TOTP{Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"},
		{TOTP: TOTP{Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"},
		{TOTP: TOTP{Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"},
		{TOTP: TOTP{Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"},
		{TOTP: TOTP{Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"},
		{TOTP: TOTP{Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"},
	}
	for _, test := range testcases {
		test.Secret = base32.StdEncoding.EncodeToString([]byte(test.Secret)) // Convert secret to base32
		otp, err := test.Generate()
		if otp != test.Output || err != nil {
			t.Errorf("Expected: %v, Received: %v\n", test.Output, otp)
		}
	}
}

func TestHOTP(t *testing.T) {
	testcases := []HOTPTest{
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 0}, Output: "755224"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 1}, Output: "287082"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 2}, Output: "359152"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 3}, Output: "969429"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 4}, Output: "338314"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 5}, Output: "254676"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 6}, Output: "287922"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 7}, Output: "162583"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 8}, Output: "399871"},
		{HOTP: HOTP{Secret: "12345678901234567890", Digits: 6, Counter: 9}, Output: "520489"},
	}

	for _, test := range testcases {
		test.Secret = base32.StdEncoding.EncodeToString([]byte(test.Secret)) // Convert secret to base32
		otp, err := test.Generate()
		if otp != test.Output || err != nil {
			t.Errorf("Expected: %v, Received: %v\n", test.Output, otp)
		}
	}
}
