package wireguardhttps

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

func NewSQLiteDatabase(path string) (Database, error) {
	db, err := gorm.Open("sqlite3", path)
	if err != nil {
		return nil, wrapPackageError(err)
	}
	return &dataOperations{db: db}, nil
}
