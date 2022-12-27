package api

import (
	"github.com/ZaphCode/auth-jwt-app/controllers/auth"
	"github.com/ZaphCode/auth-jwt-app/repositories/user"
	"github.com/ZaphCode/auth-jwt-app/services"
	"github.com/gofiber/fiber/v2"
)

func Setup() *fiber.App {

	app := fiber.New()

	//* Auth Routes setup
	repo := user.NewUserRepository(user.GetPGSQLConnection())
	userService := services.NewUserService(repo)
	authService := services.NewAuthService()
	validationService := services.NewValidationService()
	authController := auth.NewAuthController(authService, userService, validationService)

	CreateAuthRoutes(app.Group("/api/auth"), *authController)

	return app
}
