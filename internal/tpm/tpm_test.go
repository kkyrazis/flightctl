package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	agent_config "github.com/flightctl/flightctl/internal/agent/config"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// generateEKCertWithRealPublicKey creates a certificate using the actual TPM EK public key
func generateEKCertWithRealPublicKey(tmpPublic *tpm2.TPM2BPublic) ([]byte, error) {
	// Get the TPM public key contents
	publicContents, err := tmpPublic.Contents()
	if err != nil {
		return nil, err
	}

	// Extract the RSA public key
	rsaUnique, err := publicContents.Unique.RSA()
	if err != nil {
		return nil, err
	}

	// Create Go RSA public key from TPM data
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(rsaUnique.Buffer),
		E: 65537, // Standard RSA exponent
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"FlightCTL Test EK"},
			Country:      []string{"US"},
			Locality:     []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	// Generate a temporary private key for signing the certificate
	tempPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create self-signed certificate using the actual EK public key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, rsaPublicKey, tempPrivateKey)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

// writeEKCertToTPM writes the endorsement key certificate to TPM NVRAM
func writeEKCertToTPM(conn io.ReadWriter, index tpm2.TPMHandle, certDER []byte) error {
	// Define NVRAM space with appropriate attributes for EK certificate
	// Remove AuthRead to allow unauthenticated reads by Owner hierarchy
	nvPublic := tpm2.TPMSNVPublic{
		NVIndex: index,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			PPWrite:        true, // Platform hierarchy can write
			PPRead:         true, // Platform hierarchy can read
			OwnerRead:      true, // Owner hierarchy can read (no auth required)
			NoDA:           true, // No dictionary attack protection
			PlatformCreate: true, // Platform created
			// Removed AuthRead to allow unauthenticated Owner reads
		},
		DataSize: uint16(len(certDER)),
	}

	cmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHPlatform,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(nvPublic),
	}

	_, err := cmd.Execute(transport.FromReadWriter(conn))
	if err != nil {
		return err
	}

	// Write certificate data to NVRAM
	writeCmd := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHPlatform,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: index,
			Name:   tpm2.TPM2BName{}, // Empty name for platform auth
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: certDER,
		},
		Offset: 0,
	}

	_, err = writeCmd.Execute(transport.FromReadWriter(conn))
	return err
}

// setupFakeEKCertificate sets up a fake RSA endorsement key certificate in the TPM simulator
func setupFakeEKCertificate(conn io.ReadWriter) error {
	// First, create the RSA endorsement key in the TPM
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}

	createResp, err := createEKCmd.Execute(transport.FromReadWriter(conn))
	if err != nil {
		return err
	}

	// Ensure the EK handle is always flushed to prevent resource leaks
	defer func() {
		flushCmd := tpm2.FlushContext{
			FlushHandle: createResp.ObjectHandle,
		}
		_, _ = flushCmd.Execute(transport.FromReadWriter(conn)) // Ignore errors during cleanup
	}()

	// Get the public key from the created EK
	readPublicCmd := tpm2.ReadPublic{
		ObjectHandle: createResp.ObjectHandle,
	}

	publicResp, err := readPublicCmd.Execute(transport.FromReadWriter(conn))
	if err != nil {
		return err
	}

	// Generate a certificate using the actual EK public key
	certDER, err := generateEKCertWithRealPublicKey(&publicResp.OutPublic)
	if err != nil {
		return err
	}

	return writeEKCertToTPM(conn, tpm2.TPMHandle(client.EKCertNVIndexRSA), certDER)
}

// performClientOperations performs a standard set of client operations and returns the public key
func performClientOperations(t *testing.T, c *Client, ctx context.Context, testSuffix string) crypto.PublicKey {
	require := require.New(t)

	// Ensure the CSR generation flow doesn't fail
	csr, err := c.MakeCSR("test-name", make([]byte, 32))
	require.NoError(err)
	require.NotEmpty(csr)

	// Test VendorInfoCollector
	s := c.VendorInfoCollector(ctx)
	require.NotEmpty(s)

	// Ensure basic signing methods work
	signer := c.GetSigner()
	require.NotNil(signer)

	public := c.Public()
	require.NotNil(public)

	// Test signing functionality
	testData1 := []byte("test data for signing " + testSuffix)
	hash1 := sha256.Sum256(testData1)
	signature1, err := signer.Sign(rand.Reader, hash1[:], crypto.SHA256)
	require.NoError(err)
	require.NotEmpty(signature1)

	// Verify the signature using the public key - handle both ECDSA and RSA
	switch pubKey := public.(type) {
	case *ecdsa.PublicKey:
		// For ECDSA, we need to parse the DER-encoded signature
		// The signer should return DER-encoded signatures
		valid := ecdsa.VerifyASN1(pubKey, hash1[:], signature1)
		require.True(valid, "ECDSA signature verification failed")
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash1[:], signature1)
		require.NoError(err)
	default:
		require.Fail("unsupported public key type")
	}

	// Test signing different data
	testData2 := []byte("different test data " + testSuffix)
	hash2 := sha256.Sum256(testData2)
	signature2, err := signer.Sign(rand.Reader, hash2[:], crypto.SHA256)
	require.NoError(err)
	require.NotEmpty(signature2)

	// Verify the second signature
	switch pubKey := public.(type) {
	case *ecdsa.PublicKey:
		valid := ecdsa.VerifyASN1(pubKey, hash2[:], signature2)
		require.True(valid, "ECDSA signature verification failed")
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash2[:], signature2)
		require.NoError(err)
	}

	// Ensure signatures are different for different data
	require.NotEqual(signature1, signature2)

	return public
}

func TestClient_Integration(t *testing.T) {
	testCases := []struct {
		name            string
		enableOwnership bool
	}{
		{
			name:            "client with ownership enabled",
			enableOwnership: true,
		},
		{
			name:            "client with ownership disabled",
			enableOwnership: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			sim, err := simulator.Get()
			require.NoError(err)
			defer sim.Close()

			// Set up fake RSA endorsement key certificate in the simulator
			err = setupFakeEKCertificate(sim)
			require.NoError(err)

			rw := fileio.NewReadWriter(fileio.WithTestRootDir(t.TempDir()))

			c, err := newClientWithConnection(sim, log.NewPrefixLogger("test"), rw, &agent_config.Config{
				TPM: agent_config.TPM{
					Enabled:         true,
					Path:            agent_config.DefaultTPMDevicePath,
					PersistencePath: agent_config.DefaultTPMKeyBlobFile,
					EnableOwnership: tc.enableOwnership,
				},
			}, "test-model", "test-serial")
			require.NoError(err)

			ctx := context.Background()

			// Perform initial client operations and store the public key for comparison
			originalPublic := performClientOperations(t, c, ctx, "initial")
			err = c.Close(ctx)
			require.NoError(err)

			// Reset the TPM simulator to simulate a reboot
			err = sim.Reset()
			require.NoError(err)

			// Create a new client with the same configuration
			c2, err := newClientWithConnection(sim, log.NewPrefixLogger("test"), rw, &agent_config.Config{
				TPM: agent_config.TPM{
					Enabled:         true,
					Path:            agent_config.DefaultTPMDevicePath,
					PersistencePath: agent_config.DefaultTPMKeyBlobFile,
					EnableOwnership: tc.enableOwnership,
				},
			}, "test-model", "test-serial")
			require.NoError(err)
			// Perform the same client operations after reset
			public2 := performClientOperations(t, c2, ctx, "after-reset")

			// Verify that the public key is the same after reset (persistent key)
			require.Equal(originalPublic, public2, "Public key should remain the same after TPM reset")

			// Test Clear operation - should reset TPM hierarchy and clear storage
			err = c2.Clear()
			require.NoError(err)

			err = c2.Close(ctx)
			require.NoError(err)

			// Create a third client to verify Clear worked - TPM hierarchy reset and storage cleared
			c3, err := newClientWithConnection(sim, log.NewPrefixLogger("test"), rw, &agent_config.Config{
				TPM: agent_config.TPM{
					Enabled:         true,
					Path:            agent_config.DefaultTPMDevicePath,
					PersistencePath: agent_config.DefaultTPMKeyBlobFile,
					EnableOwnership: tc.enableOwnership,
				},
			}, "test-model", "test-serial")
			require.NoError(err)

			// Verify the third client can operate (TPM hierarchy reset successful)
			public3 := performClientOperations(t, c3, ctx, "after-clear")

			// Verify that the public key is different after Clear (fresh keys generated)
			require.NotEqual(originalPublic, public3, "Public key should be different after TPM Clear operation")

			err = c3.Close(ctx)
			require.NoError(err)
		})
	}
}
