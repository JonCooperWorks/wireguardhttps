package wireguardhttps

import (
	"net"
)

type Database interface {
	Initialize() error
	AllocateSubnet(addresses []net.IP) error
	CreateDevice(owner UserProfile, name, os string) (Device, error)
	Devices(owner UserProfile) ([]Device, error)
	Device(owner UserProfile, deviceID int) (Device, error)
	RemoveDevice(owner UserProfile, device Device) error
	RegisterUser(name, email, authPlatformUserID, authPlatform string) (UserProfile, error)
	GetUser(userID int) (UserProfile, error)
	DeleteUser(userID int) error
	Close() error
}

type RecordNotFoundError struct {
	err error
}

func (r *RecordNotFoundError) Error() string {
	return r.err.Error()
}
