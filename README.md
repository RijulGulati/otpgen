# otpgen
Library to generate TOTP/HOTP codes

## Installation

```sh
go get -u github.com/grijul/otpgen
```

## Usage
Here is a sample demonstration

```go
package main

import (
	"fmt"

	"github.com/grijul/otpgen"
)

func main() {

	// Generate TOTP
	totp := otpgen.TOTP{
		Secret:    "testpass",
		Digits:    8,        //(optional) (default: 6)
		Algorithm: "SHA256", //(optional) (default: SHA1)
		Period:    45,       //(optional) (default: 30)
		UnixTime:  11111111, //(optional) (default: Current Unix Time)
	}

	if otp, err := totp.Generate(); err == nil {
		fmt.Println(otp)
	} else {
		fmt.Println(err.Error())
	}

	// Generate HOTP
	hotp := otpgen.HOTP{
		Secret:  "testsecret",
		Counter: 100, //(default: 0)
		Digits:  8,   //(optional) (default: 6)
	}

	if otp, err := hotp.Generate(); err == nil {
		fmt.Println(otp)
	} else {
		fmt.Println(err.Error())
	}
}
```

# Licence
[MIT](https://github.com/grijul/otpgen/blob/main/LICENSE)
