// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package credential

func Equal(a, b Credential) bool {
	switch a := a.(type) {
	case *AWSCreds:
		b, ok := b.(*AWSCreds)

		return ok && a.IsEqual(b)
	case *Oauth2Creds:
		b, ok := b.(*Oauth2Creds)

		return ok && a.IsEqual(b)
	case *Token:
		b, ok := b.(*Token)

		return ok && a.IsEqual(b)
	default:
		return false
	}
}

func (a *Token) IsEqual(b *Token) bool {
	return a.Token == b.Token
}

func (a *Oauth2Creds) IsEqual(b *Oauth2Creds) bool {
	if a.AccessToken != b.AccessToken {
		return false
	}

	if a.TokenType != b.TokenType {
		return false
	}

	if a.RefreshToken != b.RefreshToken {
		return false
	}

	if a.Expiry != b.Expiry {
		return false
	}

	if a.ExpiresIn != b.ExpiresIn {
		return false
	}

	return true
}

func (a *AWSCreds) IsEqual(b *AWSCreds) bool {
	if a.AccessKeyID != b.AccessKeyID {
		return false
	}

	if a.SecretAccessKey != b.SecretAccessKey {
		return false
	}

	if a.SessionToken != b.SessionToken {
		return false
	}

	if a.Source != b.Source {
		return false
	}

	if a.CanExpire != b.CanExpire {
		return false
	}

	if a.Expires != b.Expires {
		return false
	}

	if a.AccountID != b.AccountID {
		return false
	}

	return true
}
