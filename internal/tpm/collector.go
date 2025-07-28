package tpm

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/flightctl/flightctl/pkg/log"
	legacy "github.com/google/go-tpm/legacy/tpm2"
)

// systemCollector handles TPM-based system information collection and measurements
type systemCollector struct {
	conn           *connectionManager
	keyMgr         *keyManager
	attestationMgr *attestationManager
	log            *log.PrefixLogger
}

// newSystemCollector creates a new system collector with dependencies
func newSystemCollector(conn *connectionManager, keyMgr *keyManager, attestationMgr *attestationManager, log *log.PrefixLogger) *systemCollector {
	return &systemCollector{
		conn:           conn,
		keyMgr:         keyMgr,
		attestationMgr: attestationMgr,
		log:            log,
	}
}

// vendorInfoCollector returns TPM vendor information as a string for system info collection.
func (sc *systemCollector) vendorInfoCollector(ctx context.Context) string {
	if sc.conn.conn == nil {
		if sc.log != nil {
			sc.log.Errorf("Cannot get TPM vendor info: TPM connection is unavailable")
		}
		return ""
	}
	info, err := sc.vendorInfo()
	if err != nil {
		if sc.log != nil {
			sc.log.Errorf("Unable to get TPM vendor info: %v", err)
		}
		return ""
	}
	return string(info)
}

// attestationCollector returns TPM attestation as a string for system info collection.
func (sc *systemCollector) attestationCollector(ctx context.Context) string {
	if sc.conn.conn == nil {
		if sc.log != nil {
			sc.log.Errorf("Cannot get TPM attestation: TPM connection is unavailable")
		}
		return ""
	}
	lak := sc.keyMgr.lakHandle()
	if lak == nil {
		if sc.log != nil {
			sc.log.Errorf("Cannot get TPM attestation: LAK is not available")
		}
		return ""
	}

	return sc.attestationMgr.attestationCollector()
}

// vendorInfo returns the TPM manufacturer information.
// This can be used to identify the TPM vendor and model.
func (sc *systemCollector) vendorInfo() ([]byte, error) {
	if sc.conn.conn == nil {
		return nil, fmt.Errorf("cannot get TPM vendor info: no conn available")
	}
	vendorInfo, err := legacy.GetManufacturer(sc.conn.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM manufacturer info: %w", err)
	}
	return vendorInfo, nil
}

// readPCRValues reads PCR values from the TPM and populates the provided map.
// The map keys are formatted as "pcr01", "pcr02", etc., and values are hex-encoded.
func (sc *systemCollector) readPCRValues(measurements map[string]string) error {
	if sc.conn.conn == nil {
		return nil
	}
	for pcr := 1; pcr <= 16; pcr++ {
		key := fmt.Sprintf("pcr%02d", pcr)
		val, err := legacy.ReadPCR(sc.conn.conn, pcr, legacy.AlgSHA256)
		if err != nil {
			return fmt.Errorf("failed to read PCR %d: %w", pcr, err)
		}
		measurements[key] = hex.EncodeToString(val)
	}
	return nil
}
