package wireguardhttps

import (
	"net"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	gormbulk "github.com/t-tiger/gorm-bulk-insert"
)

type postgresDatabase struct {
	db *gorm.DB
}

func NewPostgresDatabase(connectionString string) (Database, error) {
	db, err := gorm.Open("postgres", connectionString)
	if err != nil {
		return nil, wrapPackageError(err)
	}
	return &postgresDatabase{db: db}, nil
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

func (pd *postgresDatabase) Initialize() error {
	return wrapPackageError(pd.db.AutoMigrate(&UserProfile{}, &Device{}, IPAddress{}).Error)
}

func (pd *postgresDatabase) Close() error {
	return wrapPackageError(pd.db.Close())
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
		return wrapPackageError(err)
	}
	return nil
}

func (pd *postgresDatabase) createIPAddress() (IPAddress, error) {
	var ipAddress IPAddress
	row := pd.db.Raw("SELECT ip.address FROM ip_addresses ip WHERE NOT EXISTS (SELECT d.ip_address FROM devices d WHERE  d.ip_address = ip.address) LIMIT 1").Row()
	err := row.Scan(&ipAddress)
	return ipAddress, err
}

func (pd *postgresDatabase) CreateDevice(owner UserProfile, name, os, publicKey string) (Device, error) {
	var device Device
	err := pd.db.Transaction(func(db *gorm.DB) error {
		ipAddress, err := pd.createIPAddress()
		if err != nil {
			return err
		}

		device = Device{
			Name:      name,
			OS:        os,
			PublicKey: publicKey,
			IPAddress: ipAddress.Address,
		}
		err = pd.db.Create(&device).Error
		if err != nil {
			return err
		}
		return nil
	})
	return device, wrapPackageError(err)
}

func (pd *postgresDatabase) RekeyDevice(owner UserProfile, publicKey string, device Device) (Device, error) {
	return Device{}, nil
}

func (pd *postgresDatabase) Devices(owner UserProfile) ([]Device, error) {
	var devices []Device
	err := pd.db.Find(&devices).Where("owner = ?", owner.ID).Error
	return devices, wrapPackageError(err)
}

func (pd *postgresDatabase) Device(owner UserProfile, deviceID int) (Device, error) {
	var device Device
	err := pd.db.First(device, deviceID).Where("owner = ?", owner.ID).Error
	return device, wrapPackageError(err)
}

func (pd *postgresDatabase) RemoveDevice(owner UserProfile, device Device) error {
	return nil
}

func (pd *postgresDatabase) RegisterUser(name, email, authPlatformUserID, authPlatform string) (UserProfile, error) {
	user := UserProfile{
		Name:               name,
		Email:              email,
		AuthPlatformUserID: authPlatformUserID,
		AuthPlatform:       authPlatform,
	}
	err := pd.db.FirstOrCreate(&user).Error
	return user, wrapPackageError(err)
}

func (pd *postgresDatabase) GetUser(userID int) (UserProfile, error) {
	var user UserProfile
	err := pd.db.First(user, userID).Error
	return user, wrapPackageError(err)
}

func (pd *postgresDatabase) DeleteUser(userID int) error {
	return nil
}
