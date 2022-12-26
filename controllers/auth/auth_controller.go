package auth

import (
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

	accessToken, err := c.authService.CreateJWToken(map[string]any{
		"user_id": user.ID,
		"role":    user.Role,
	}, time.Minute*5)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	refreshToken, err := c.authService.CreateJWToken(map[string]any{
		"user_id": user.ID,
		"role":    user.Role,
	}, time.Hour*24*5)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	return ctx.Status(fiber.StatusAccepted).JSON(apiUtils.SuccessResponse{
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

	user, err := c.userService.GetByEmail(body.Email)

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	accessToken, err := c.authService.CreateJWToken(map[string]any{
		"user_id": user.ID,
		"role":    user.Role,
	}, time.Minute*5)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	refreshToken, err := c.authService.CreateJWToken(map[string]any{
		"user_id": user.ID,
		"role":    user.Role,
	}, time.Hour*24*5)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(apiUtils.ErrorResponse{
			Status:  "fail",
			Message: err.Error(),
		})
	}

	return ctx.Status(fiber.StatusAccepted).JSON(apiUtils.SuccessResponse{
		Status:  "success",
		Message: "User created",
		Data: fiber.Map{
			"user":          user,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
	})
}
