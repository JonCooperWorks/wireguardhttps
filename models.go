package wireguardhttps

import (
	"net"

	"github.com/jinzhu/gorm"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// IPAddress is a single IP address.
// IPAddresses are meant to be allocated at program initialization and all stored in the database.
// For example, if wireguardhttps is initialized with the subnet 10.0.0.0/24, an entry will be created in this table for every IP address between 10.0.0.0 and 10.0.0.255.
type IPAddress struct {
	gorm.Model
	Address string `gorm:"PRIMARY_KEY"`
}

// Device is a connected Wireguard peer.
// Devices must be assigned an unassigned IP address from the `IPAddress` table
// Each device must have a unique IP address and public key, and we use the UNIQUE SQL constraint to enforce this.
type Device struct {
	gorm.Model
	IP        IPAddress `gorm:"foreignkey:IPAddress"`
	IPAddress net.IP    `gorm:"UNIQUE"`
	Name      string
	OS        string
	User      UserProfile
	PublicKey wgtypes.Key `gorm:"UNIQUE"`
}

// UserProfile represents a user who authenticated using an OpenID integration.
// We maintain as little information as possible about users to make this application a less attractive target to hackers.
type UserProfile struct {
	gorm.Model
	Name               string
	Email              string
	AuthPlatformUserID string
	AuthPlatform       string
}
