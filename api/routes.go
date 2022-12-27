package api

import (
	"github.com/ZaphCode/auth-jwt-app/controllers/auth"
	"github.com/gofiber/fiber/v2"
)

func CreateAuthRoutes(router fiber.Router, authController auth.AuthController) {
	router.Post("/signup", authController.SignUp)
	router.Post("/signin", authController.SignIn)
	router.Get("/me", authController.JWTRequiredMiddleware, authController.AuthUser)
	router.Get("/refresh", authController.RefreshToken)
}
