//go:build amd64 || arm64

package tpm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetQuote(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	_, err := data.client.keyManager.generateSRKPrimary()
	require.NoError(err)

	lak, err := data.client.keyManager.ensureLAK()
	require.NoError(err)

	quote, err := data.client.GetQuote(data.nonce, lak, data.pcrSel)
	require.NoError(err)
	require.NotNil(quote)
	require.NotEmpty(quote.Quote)
	require.NotEmpty(quote.RawSig)
	require.NotNil(quote.Pcrs)
	require.NotEmpty(quote.Pcrs.Pcrs)
}

func TestGetAttestation(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	_, err := data.client.keyManager.generateSRKPrimary()
	require.NoError(err)

	lak, err := data.client.keyManager.ensureLAK()
	require.NoError(err)

	attestation, err := data.client.GetAttestation(data.nonce, lak)
	require.NoError(err)
	require.NotNil(attestation)
	require.NotEmpty(attestation.AkPub)
	require.NotEmpty(attestation.Quotes)
	require.Len(attestation.Quotes, 1)

	// Check the quote within the attestation
	quote := attestation.Quotes[0]
	require.NotEmpty(quote.Quote)
	require.NotEmpty(quote.RawSig)
	require.NotNil(quote.Pcrs)
}

func TestReadPCRValues(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, false)
	defer cleanup()

	measurements := make(map[string]string)

	err := data.client.ReadPCRValues(measurements)
	require.NoError(err)
}
