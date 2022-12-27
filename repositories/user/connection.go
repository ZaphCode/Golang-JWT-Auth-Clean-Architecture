package user

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetPGSQLConnection() *gorm.DB {
	db, err := gorm.Open(postgres.Open(os.Getenv("PGSQL_DNS")))

	if err != nil {
		log.Fatal(err.Error(), "Connection error")
	}

	return db
}
