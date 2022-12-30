package auth

import (
	"os"
	"time"

	"github.com/ZaphCode/auth-jwt-app/controllers/auth/dtos"
	"github.com/ZaphCode/auth-jwt-app/domain"
	"github.com/ZaphCode/auth-jwt-app/services"
	apiUtils "github.com/ZaphCode/auth-jwt-app/utils"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

//* Constructor
func NewAuthController(
	authSrv services.AuthService,
	userSvc domain.UserService,
	validationSvc services.ValidationService,
) *AuthController {
	return &AuthController{
		authService:       authSrv,
		userService:       userSvc,
		validationService: validationSvc,
	}
}

//* Controller
type AuthController struct {
	authService       services.AuthService
	userService       domain.UserService
	validationService services.ValidationService
}

//* Hadlers
func (c AuthController) SignUp(ctx *fiber.Ctx) error {
	body := dtos.SignUpDTO{}

	if err := ctx.BodyParser(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Error parsing de request body",
			Detail:  err.Error(),
		})
	}

	if err := c.validationService.Validate(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Validation error",
			Detail:  err,
		})
	}

	user := body.AdaptToUser()

	if err := c.userService.Create(&user); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Creating user error",
			Detail:  err.Error(),
		})
	}

	accessToken, refreshToken, err := c.authService.CreateAccessAndRefreshJWTokens(
		services.JWTClaims{
			ID:   user.ID,
			Role: user.Role,
		},
		time.Minute*5, time.Hour*24*5,
	)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     os.Getenv("REFRESH_TOKEN_COOKIE"),
		Value:    refreshToken,
		HTTPOnly: true,
		Expires:  time.Now().Add(24 * 5 * time.Hour),
		SameSite: "lax",
	})

	return ctx.Status(fiber.StatusCreated).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "User created",
		Data: fiber.Map{
			"user":          user,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
	})
}

func (c AuthController) SignIn(ctx *fiber.Ctx) error {
	body := dtos.SignInDTO{}

	if err := ctx.BodyParser(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Error parsing the request body",
			Detail:  err.Error(),
		})
	}

	if err := c.validationService.Validate(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Validation error",
			Detail:  err,
		})
	}

	user, err := c.userService.GetByEmail(body.Email)

	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Invalid password",
		})
	}

	accessToken, refreshToken, err := c.authService.CreateAccessAndRefreshJWTokens(
		services.JWTClaims{
			ID:   user.ID,
			Role: user.Role,
		},
		time.Minute*5, time.Hour*24*5,
	)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Error creating tokens",
		})
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     os.Getenv("REFRESH_TOKEN_COOKIE"),
		Value:    refreshToken,
		HTTPOnly: true,
		Expires:  time.Now().Add(24 * 5 * time.Hour),
		SameSite: "lax",
	})

	return ctx.Status(fiber.StatusOK).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "Success sigh in",
		Data: fiber.Map{
			"user":          user,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
	})
}

func (c AuthController) AuthUser(ctx *fiber.Ctx) error {
	userData := ctx.Locals("user_data").(*services.JWTClaims)

	user, err := c.userService.GetByID(userData.ID)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "User data retrived",
		Data:    user,
	})
}

func (c AuthController) RefreshToken(ctx *fiber.Ctx) error {
	method := ctx.Query("method", "cookie")

	var refreshToken string

	switch method {
	case "cookie":
		refreshToken = ctx.Cookies(os.Getenv("REFRESH_TOKEN_COOKIE"))
	case "header":
		refreshToken = ctx.Get(os.Getenv("REFRESH_TOKEN_HEADER"))
	default:
		refreshToken = ctx.Cookies(os.Getenv("REFRESH_TOKEN_COOKIE"))
	}

	if refreshToken == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Missing refresh token",
		})
	}

	claims, err := c.authService.DecodeJWToken(refreshToken, true)

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Invalid refresh token",
			Detail:  err.Error(),
		})
	}

	accessToken, err := c.authService.CreateJWToken(*claims, time.Minute*5, false)

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Creating token error",
			Detail:  err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "Token refreshed",
		Data:    accessToken,
	})
}

//* Middlewares
func (c AuthController) JWTRequiredMiddleware(ctx *fiber.Ctx) error {
	accessToken := ctx.Get(os.Getenv("ACCESS_TOKEN_HEADER"))

	if accessToken == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Missing access token",
		})
	}

	decodedTokenClaims, err := c.authService.DecodeJWToken(accessToken, false)

	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Invalid access token",
			Detail:  err.Error(),
		})
	}

	ctx.Locals("user_data", decodedTokenClaims)

	return ctx.Next()
}
