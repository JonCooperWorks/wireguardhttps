package wireguardhttps

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func NewPostgresDatabase(connectionString string) (Database, error) {
	db, err := gorm.Open("postgres", connectionString)
	if err != nil {
		return nil, wrapPackageError(err)
	}
	return &dataOperations{db: db}, nil
}
