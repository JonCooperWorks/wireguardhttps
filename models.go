package wireguardhttps

import (
	"net"

	"github.com/jinzhu/gorm"
)

type IPAddress struct {
	gorm.Model
	Address net.IP `gorm:"PRIMARY_KEY"`
}

type Device struct {
	gorm.Model
	IPAddress IPAddress `gorm:"UNIQUE"`
	Name      string
	OS        string
	User      User
}

type User struct {
	gorm.Model
	Username          string
	Name              string
	UserPrincipalName string
}
