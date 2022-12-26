package main

import (
	"fmt"
	"log"

	"github.com/ZaphCode/auth-jwt-app/api"
)

func main() {
	fmt.Println("TEST")

	app := api.Setup()

	log.Fatal(app.Listen(":8000"))
}
