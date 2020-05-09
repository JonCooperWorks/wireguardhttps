package wireguardhttps

import (
	"net"

	"github.com/jinzhu/gorm"
	"github.com/joncooperworks/wgrpcd"
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
	return wrapPackageError(d.db.AutoMigrate(&UserProfile{}, &Device{}, &IPAddress{}).Error)
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
	err := d.db.Raw("SELECT * FROM ip_addresses ip WHERE NOT EXISTS (SELECT d.ip_address FROM devices d WHERE  d.ip_address = ip.address) LIMIT 1").
		Scan(&ipAddress).
		Error
	return ipAddress, err
}

func (d *dataOperations) CreateDevice(owner UserProfile, name, os string, deviceFunc DeviceFunc) (Device, *wgrpcd.PeerConfigInfo, error) {
	var device Device
	var credentials *wgrpcd.PeerConfigInfo
	err := d.db.Transaction(func(db *gorm.DB) error {
		ipAddress, err := d.createIPAddress()
		if err != nil {
			return err
		}

		credentials, err = deviceFunc(ipAddress)
		if err != nil {
			return err
		}

		device = Device{
			Name:      name,
			OS:        os,
			PublicKey: credentials.PublicKey,
			IPAddress: ipAddress.Address,
			Owner:     owner,
		}
		err = d.db.Create(&device).
			Error
		if err != nil {
			return err
		}

		return nil
	})
	return device, credentials, wrapPackageError(err)
}

func (d *dataOperations) RekeyDevice(owner UserProfile, device Device, rekeyFunc DeviceFunc) (Device, *wgrpcd.PeerConfigInfo, error) {
	var credentials *wgrpcd.PeerConfigInfo
	err := d.db.Transaction(func(db *gorm.DB) error {
		var err error
		credentials, err = rekeyFunc(device.IP)
		if err != nil {
			return err
		}

		device.PublicKey = credentials.PublicKey
		err = db.Save(&device).
			Error
		if err != nil {
			return err
		}

		return nil
	})
	return device, credentials, wrapPackageError(err)
}

func (d *dataOperations) Devices(owner UserProfile) ([]Device, error) {
	var devices []Device
	err := d.db.Preload("IP").
		Preload("Owner").
		Where("owner_id = ?", owner.ID).
		Find(&devices).
		Error
	return devices, wrapPackageError(err)
}

func (d *dataOperations) Device(owner UserProfile, deviceID int) (Device, error) {
	var device Device
	err := d.db.Preload("IP").
		Preload("Owner").
		Where("owner_id = ?", owner.ID).
		First(&device, deviceID).
		Error
	return device, wrapPackageError(err)
}

func (d *dataOperations) RemoveDevice(owner UserProfile, device Device, deleteFunc DeleteFunc) error {
	err := deleteFunc()
	if err != nil {
		return err
	}

	err = d.db.Where("owner_id = ?", owner.ID).
		Delete(&device).Error
	return wrapPackageError(err)
}

func (d *dataOperations) RegisterUser(authPlatformUserID, authPlatform string) (UserProfile, error) {
	user := UserProfile{
		AuthPlatformUserID: authPlatformUserID,
		AuthPlatform:       authPlatform,
	}
	err := d.db.FirstOrCreate(&user, UserProfile{AuthPlatformUserID: authPlatformUserID}).
		Error
	return user, wrapPackageError(err)
}

func (d *dataOperations) GetUser(userID int) (UserProfile, error) {
	var user UserProfile
	err := d.db.First(user, userID).
		Error
	return user, wrapPackageError(err)
}

func (d *dataOperations) DeleteUser(userID int) error {
	return nil
}
