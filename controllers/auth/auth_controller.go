package auth

import (
	"strings"
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
			Message: "Error creating jwtokens",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "User created",
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
		Message: "test",
		Data:    user,
	})
}

func (c AuthController) RefreshToken(ctx *fiber.Ctx) error {
	refreshToken := ctx.Get("Token", "")

	claims, err := c.authService.DecodeJWToken(refreshToken)

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Invalid Token",
			Detail:  err.Error(),
		})
	}

	accessToken, err := c.authService.CreateJWToken(*claims, time.Minute*5)

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Creating token error",
			Detail:  err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "User created",
		Data:    accessToken,
	})
}

//* Middlewares
func (c AuthController) JWTRequiredMiddleware(ctx *fiber.Ctx) error {
	authHeader := ctx.Get("Authorization", "")

	if authHeader == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "No token provided",
		})
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ctx.Status(fiber.StatusNotAcceptable).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Invalid token format",
		})
	}

	access_token := strings.Split(authHeader, "Bearer ")[1]

	decoded_token_claims, err := c.authService.DecodeJWToken(access_token)

	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: "Invalid access token",
		})
	}

	ctx.Locals("user_data", decoded_token_claims)

	return ctx.Next()
}
