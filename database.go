package wireguardhttps

import (
	"net"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	gormbulk "github.com/t-tiger/gorm-bulk-insert"
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

type postgresDatabase struct {
	db *gorm.DB
}

func NewPostgresDatabase(connectionString string) (Database, error) {
	db, err := gorm.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	return &postgresDatabase{db: db}, nil
}

func (pd *postgresDatabase) Initialize() error {
	return pd.db.AutoMigrate(&UserProfile{}, &Device{}, IPAddress{}).Error
}

func (pd *postgresDatabase) Close() error {
	return pd.db.Close()
}

func (pd *postgresDatabase) AllocateSubnet(addresses []net.IP) error {
	var databaseInput []interface{}
	// Don't allocate broadcast or network address.
	for _, address := range addresses[1 : len(addresses)-1] {
		ipAddress := IPAddress{
			Address: address.String(),
		}
		databaseInput = append(databaseInput, ipAddress)
	}

	err := gormbulk.BulkInsert(pd.db, databaseInput, 3000)
	if err != nil {
		return err
	}
	return nil
}

func (pd *postgresDatabase) CreateDevice(owner UserProfile, name, os string) (Device, error) {
	return Device{}, nil
}

func (pd *postgresDatabase) Devices(owner UserProfile) ([]Device, error) {
	return []Device{}, nil
}

func (pd *postgresDatabase) Device(owner UserProfile, deviceID int) (Device, error) {
	return Device{}, nil
}

func (pd *postgresDatabase) RemoveDevice(owner UserProfile, device Device) error {
	return nil
}

func (pd *postgresDatabase) RegisterUser(name, email, authPlatformUserID, authPlatform string) (UserProfile, error) {
	return UserProfile{}, nil
}

func (pd *postgresDatabase) GetUser(userID int) (UserProfile, error) {
	var user UserProfile
	err := pd.db.First(user, userID).Error
	return user, err
}

func (pd *postgresDatabase) DeleteUser(userID int) error {
	return nil
}
