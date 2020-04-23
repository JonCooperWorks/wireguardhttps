package wireguardhttps

import (
	"net"

	"github.com/jinzhu/gorm"
	gormbulk "github.com/t-tiger/gorm-bulk-insert"
)

type dataOperations struct {
	db *gorm.DB
}

func wrapPackageError(err error) error {
	if err == nil {
		return nil
	}

	if gorm.IsRecordNotFoundError(err) {
		return &RecordNotFoundError{err: err}
	}
	return &DatabaseError{err: err}
}

func (d *dataOperations) Initialize() error {
	return wrapPackageError(d.db.AutoMigrate(&UserProfile{}, &Device{}, IPAddress{}).Error)
}

func (d *dataOperations) Close() error {
	return wrapPackageError(d.db.Close())
}

func (d *dataOperations) AllocateSubnet(addresses []net.IP) error {
	var databaseInput []interface{}
	// Don't allocate broadcast or network address.
	for _, address := range addresses[1 : len(addresses)-1] {
		ipAddress := IPAddress{
			Address: address.String(),
		}
		databaseInput = append(databaseInput, ipAddress)
	}

	err := gormbulk.BulkInsert(d.db, databaseInput, 3000)
	if err != nil {
		return wrapPackageError(err)
	}
	return nil
}

func (d *dataOperations) createIPAddress() (IPAddress, error) {
	var ipAddress IPAddress
	row := d.db.Raw("SELECT ip.address FROM ip_addresses ip WHERE NOT EXISTS (SELECT d.ip_address FROM devices d WHERE  d.ip_address = ip.address) LIMIT 1").Row()
	err := row.Scan(&ipAddress)
	return ipAddress, err
}

func (d *dataOperations) CreateDevice(owner UserProfile, name, os, publicKey string) (Device, error) {
	var device Device
	err := d.db.Transaction(func(db *gorm.DB) error {
		ipAddress, err := d.createIPAddress()
		if err != nil {
			return err
		}

		device = Device{
			Name:      name,
			OS:        os,
			PublicKey: publicKey,
			IPAddress: ipAddress.Address,
		}
		err = d.db.Create(&device).Error
		if err != nil {
			return err
		}
		return nil
	})
	return device, wrapPackageError(err)
}

func (d *dataOperations) RekeyDevice(owner UserProfile, publicKey string, device Device) (Device, error) {
	return Device{}, nil
}

func (d *dataOperations) Devices(owner UserProfile) ([]Device, error) {
	var devices []Device
	err := d.db.Find(&devices).Where("owner = ?", owner.ID).Error
	return devices, wrapPackageError(err)
}

func (d *dataOperations) Device(owner UserProfile, deviceID int) (Device, error) {
	var device Device
	err := d.db.First(device, deviceID).Where("owner = ?", owner.ID).Error
	return device, wrapPackageError(err)
}

func (d *dataOperations) RemoveDevice(owner UserProfile, device Device) error {
	return nil
}

func (d *dataOperations) RegisterUser(name, email, authPlatformUserID, authPlatform string) (UserProfile, error) {
	user := UserProfile{
		Name:               name,
		Email:              email,
		AuthPlatformUserID: authPlatformUserID,
		AuthPlatform:       authPlatform,
	}
	err := d.db.FirstOrCreate(&user).Error
	return user, wrapPackageError(err)
}

func (d *dataOperations) GetUser(userID int) (UserProfile, error) {
	var user UserProfile
	err := d.db.First(user, userID).Error
	return user, wrapPackageError(err)
}

func (d *dataOperations) DeleteUser(userID int) error {
	return nil
}
