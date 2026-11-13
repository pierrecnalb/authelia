// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/token/jwt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
)

func TestNewRFC8693TokenTypes(t *testing.T) {
	t.Run("ShouldDefaultToStaticTypes", func(t *testing.T) {
		types := oidc.NewRFC8693TokenTypes(&schema.IdentityProvidersOpenIDConnectTokenExchange{}, nil)

		require.Len(t, types, 3)

		for _, name := range []string{oidc.TokenTypeAccessToken, oidc.TokenTypeRefreshToken, oidc.TokenTypeIDToken} {
			tokenType, ok := types[name].(*rfc8693.DefaultTokenType)

			require.True(t, ok)
			assert.Equal(t, name, tokenType.Name)
		}
	})

	t.Run("ShouldBuildListedStaticTypesOnly", func(t *testing.T) {
		types := oidc.NewRFC8693TokenTypes(&schema.IdentityProvidersOpenIDConnectTokenExchange{
			TokenTypes: []string{oidc.TokenTypeAccessToken},
		}, nil)

		require.Len(t, types, 1)
		assert.Contains(t, types, oidc.TokenTypeAccessToken)
	})

	t.Run("ShouldBuildTxnTokenWithoutOptionals", func(t *testing.T) {
		types := oidc.NewRFC8693TokenTypes(&schema.IdentityProvidersOpenIDConnectTokenExchange{
			TokenTypes: []string{oidc.TokenTypeAccessToken, oidc.TokenTypeTxnToken},
			TransactionTokens: schema.IdentityProvidersOpenIDConnectTransactionTokens{
				TrustDomain:      "example.com",
				Issuer:           "https://txn.example.com",
				Lifespan:         time.Minute * 3,
				SigningAlgorithm: "RS256",
			},
		}, nil)

		require.Len(t, types, 2)

		tokenType, ok := types[oidc.TokenTypeTxnToken].(*rfc8693.TxnTokenType)

		require.True(t, ok)
		assert.Equal(t, oidc.TokenTypeTxnToken, tokenType.Name)
		assert.Equal(t, "example.com", tokenType.TrustDomain)
		assert.Equal(t, "https://txn.example.com", tokenType.Issuer)
		assert.Equal(t, time.Minute*3, tokenType.Expiry)
		assert.Equal(t, "RS256", tokenType.SigningAlg)
		assert.Nil(t, tokenType.TranscribeClaims)
		assert.Nil(t, tokenType.Replacement)
	})

	t.Run("ShouldBuildTxnTokenWithCopyAndReplacement", func(t *testing.T) {
		types := oidc.NewRFC8693TokenTypes(&schema.IdentityProvidersOpenIDConnectTokenExchange{
			TokenTypes: []string{oidc.TokenTypeTxnToken},
			TransactionTokens: schema.IdentityProvidersOpenIDConnectTransactionTokens{
				TrustDomain:           "example.com",
				CopyRequestParameters: true,
				Replacement:           schema.IdentityProvidersOpenIDConnectTransactionTokensReplacement{Enabled: true, MaxChainLength: 4},
			},
		}, oidc.NewIssuer(nil))

		tokenType, ok := types[oidc.TokenTypeTxnToken].(*rfc8693.TxnTokenType)

		require.True(t, ok)
		assert.NotNil(t, tokenType.TranscribeClaims)
		require.NotNil(t, tokenType.Replacement)
		assert.NotNil(t, tokenType.Replacement.KeyFunc)
		assert.Equal(t, 4, tokenType.Replacement.MaxChainLength)
	})
}

func TestNewIssuerKeyFunc(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := oidc.NewIssuer([]schema.JWK{{KeyID: "rsa-1", Use: oidc.KeyUseSignature, Algorithm: oidc.SigningAlgRSAUsingSHA256, Key: rsaKey}})
	keyfunc := oidc.NewIssuerKeyFunc(issuer)

	sign := func(t *testing.T, kid string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
		require.NoError(t, err)

		object, err := signer.Sign([]byte(`{"sub":"john"}`))
		require.NoError(t, err)

		compact, err := object.CompactSerialize()
		require.NoError(t, err)

		return compact
	}

	t.Run("ShouldVerifyIssuerSignedToken", func(t *testing.T) {
		token, err := jwt.ParseCustomWithClaims(sign(t, "rsa-1"), jwt.MapClaims{}, keyfunc, jose.RS256)

		require.NoError(t, err)
		assert.NoError(t, token.Valid())
	})

	t.Run("ShouldRejectUnknownKeyID", func(t *testing.T) {
		_, err := jwt.ParseCustomWithClaims(sign(t, "unknown"), jwt.MapClaims{}, keyfunc, jose.RS256)

		assert.Error(t, err)
	})
}
