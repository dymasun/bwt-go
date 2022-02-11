package bwt

import (
	"fmt"
	"strings"
)

type Parser struct {
	ValidMethods         []string // If populated, only these methods will be considered valid
	UseJSONNumber        bool     // Use JSON Number format in JSON decoder
	SkipClaimsValidation bool     // Skip claims validation during token parsing
}

func (p *Parser) ParseToBytes(tokenString string, keyfunc KeyBufFunc) ([]byte, error) {
	buf, parts, method, err := p.ParseBytesUnverified(tokenString)
	if err != nil {
		return buf, err
	}
	if keyfunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return buf, NewValidationError("no Keyfunc was provided.", ValidationErrorUnverifiable)
	}
	// Verify signing method is in the required set
	if p.ValidMethods != nil {
		var signingMethodValid = false
		var alg = method.Alg()
		for _, m := range p.ValidMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return buf, NewValidationError(fmt.Sprintf("signing method %v is invalid", alg), ValidationErrorSignatureInvalid)
		}
	}
	// Lookup key
	var key interface{}
	if key, err = keyfunc(parts); err != nil {
		// keyFunc returned an error
		if ve, ok := err.(*ValidationError); ok {
			return buf, ve
		}
		return buf, &ValidationError{Inner: err, Errors: ValidationErrorUnverifiable}
	}

	vErr := &ValidationError{}

	// Perform validation
	if err = method.Verify(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
		vErr.Inner = err
		vErr.Errors |= ValidationErrorSignatureInvalid
	}
	if vErr.valid() {
		return buf, nil
	}
	return buf, vErr
}

func (p *Parser) ParseBytesUnverified(tokenString string) (claimBytes []byte, parts []string, signingMethod SigningMethod, err error) {
	parts = strings.Split(tokenString, ".")

	if len(parts) != 3 {
		return claimBytes, parts, signingMethod, NewValidationError("token contains an invalid number of segments", ValidationErrorMalformed)
	}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return claimBytes, parts, signingMethod, NewValidationError("tokenstring should not contain 'bearer '", ValidationErrorMalformed)
		}
		return claimBytes, parts, signingMethod, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}
	method := string(headerBytes)

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return nil, parts, signingMethod, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}

	// Lookup signature method
	signingMethod = GetSigningMethod(method)
	if signingMethod == nil {
		return claimBytes, parts, signingMethod, NewValidationError("signing method (alg) is unavailable.", ValidationErrorUnverifiable)
	}

	return claimBytes, parts, signingMethod, nil
}
