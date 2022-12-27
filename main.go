package main

import (
	"log"
	"os"

	"github.com/ZaphCode/auth-jwt-app/api"
)

func main() {
	app := api.Setup()

	log.Fatal(app.Listen(":" + os.Getenv("PORT")))
}
