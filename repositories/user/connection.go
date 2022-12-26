package user

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetPGSQLConnection() *gorm.DB {
	dns := "host=localhost user=zaphkiel password=zaph_pg_pass dbname=jwt_auth_db port=5400 sslmode=disable"

	db, err := gorm.Open(postgres.Open(dns))

	if err != nil {
		log.Fatal(err.Error(), "Connection error")
	}

	return db
}
