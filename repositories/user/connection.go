package user

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetPGSQLConnection() *gorm.DB {
	dsn := os.Getenv("PGSQL_DSN")

	log.Println(dsn)

	db, err := gorm.Open(postgres.Open(dsn))

	if err != nil {
		log.Fatal(">>> Connection error", err.Error())
	}

	return db
}
