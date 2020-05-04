package wireguardhttps

import (
	"net"

	"github.com/joncooperworks/wgrpcd"
)

// Database represents all operations needed to persist devices, IP address and user info.
// Implementations of Database should ensure all errors are wrapped in the appropriate wireguardhttps error type.
type Database interface {
	Initialize() error
	AllocateSubnet(addresses []net.IP) error
	CreateDevice(owner UserProfile, name, os string, deviceFunc DeviceFunc) (Device, *wgrpcd.PeerConfigInfo, error)
	RekeyDevice(owner UserProfile, device Device, rekeyFunc RekeyFunc) (Device, *wgrpcd.PeerConfigInfo, error)
	Devices(owner UserProfile) ([]Device, error)
	Device(owner UserProfile, deviceID int) (Device, error)
	RemoveDevice(owner UserProfile, device Device) error
	RegisterUser(name, email, authPlatformUserID, authPlatform string) (UserProfile, error)
	GetUser(userID int) (UserProfile, error)
	DeleteUser(userID int) error
	Close() error
}

// DeviceFunc creates a device on the Wireguard interface and returns an error on failure.
// This allows us to take advantage of SQL transactions.
type DeviceFunc func(IPAddress) (*wgrpcd.PeerConfigInfo, error)

// RekeyFunc rekeys a device on the Wireguard interface.
type RekeyFunc func() (*wgrpcd.PeerConfigInfo, error)

// RecordNotFoundError is our package specific not found error.
// Database implementations should return this when they can't find a record, so the caller can handle this case without knowing about the underlying database.
type RecordNotFoundError struct {
	err error
}

func (r *RecordNotFoundError) Error() string {
	return r.err.Error()
}

// DatabaseError is our package specific error for all other errors.
// If a Database implementation cannot fit an error into any other error type, it should return DatabaseError.
type DatabaseError struct {
	err error
}

func (d *DatabaseError) Error() string {
	return d.err.Error()
}
