package wireguardhttps

import (
	"net"
)

// Database represents all operations needed to persist devices, IP address and user info.
// Implementations of Database should ensure all errors are wrapped in the appropriate wireguardhttps error type.
type Database interface {
	Initialize() error
	AllocateSubnet(addresses []net.IP) error
	CreateDevice(owner UserProfile, name, os, publicKey string) (Device, error)
	RekeyDevice(owner UserProfile, publicKey string, device Device) (Device, error)
	Devices(owner UserProfile) ([]Device, error)
	Device(owner UserProfile, deviceID int) (Device, error)
	RemoveDevice(owner UserProfile, device Device) error
	RegisterUser(name, email, authPlatformUserID, authPlatform string) (UserProfile, error)
	GetUser(userID int) (UserProfile, error)
	DeleteUser(userID int) error
	Close() error
}

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
