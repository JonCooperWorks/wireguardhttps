package wireguardhttps

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

func NewSQLiteDatabase(connectionString string) (Database, error) {
	db, err := gorm.Open("sqlite", connectionString)
	if err != nil {
		return nil, wrapPackageError(err)
	}
	return &dataOperations{db: db}, nil
}
