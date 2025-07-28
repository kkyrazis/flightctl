package tpm

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// connectionManager handles TPM connection lifecycle and low-level transport operations
type connectionManager struct {
	conn    io.ReadWriteCloser
	sysPath string
}

// newConnectionManager creates a new connection manager with the provided connection
func newConnectionManager(conn io.ReadWriteCloser, sysPath string) *connectionManager {
	return &connectionManager{
		conn:    conn,
		sysPath: sysPath,
	}
}

// transport returns a TPM transport from the connection
func (cm *connectionManager) transport() transport.TPM {
	return transport.FromReadWriter(cm.conn)
}

// close closes the TPM connection
func (cm *connectionManager) close() error {
	if cm.conn != nil {
		return cm.conn.Close()
	}
	return nil
}

// getPath returns the TPM device path
func (cm *connectionManager) getPath() string {
	return cm.sysPath
}

// flushContextForHandle flushes the TPM context for the specified handle if it's transient.
// Persistent handles are not flushed as they remain in the TPM across reboots.
func (cm *connectionManager) flushContextForHandle(handle tpm2.TPMHandle) error {
	// Only flush if this is a transient handle (not a persistent handle)
	if handle < persistentHandleMin || handle > persistentHandleMax {
		flushCmd := tpm2.FlushContext{
			FlushHandle: handle,
		}

		_, err := flushCmd.Execute(cm.transport())
		if err != nil {
			return fmt.Errorf("flushing context for handle 0x%x: %w", handle, err)
		}
	}
	return nil
}
