package main

import (
	"log"
	"os"

	"github.com/ZaphCode/auth-jwt-app/api"
	"github.com/ZaphCode/auth-jwt-app/utils"
)

func main() {
	utils.LoadEnv()

	app := api.Setup()

	log.Fatal(app.Listen(":" + os.Getenv("PORT")))
}
