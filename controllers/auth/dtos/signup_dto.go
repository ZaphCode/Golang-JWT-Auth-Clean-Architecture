package dtos

import (
	"encoding/json"

	"github.com/ZaphCode/auth-jwt-app/domain"
)

type SignUpDTO struct {
	Username    string          `json:"username" validate:"required,min=4,max=15"`
	Email       string          `json:"email" validate:"required,email"`
	Password    string          `json:"password" validate:"required,min=8"`
	Age         uint            `json:"age" validate:"required,number,min=15"`
	ProfileData json.RawMessage `json:"profile_data"`
}

func (d *SignUpDTO) AdaptToUser() domain.User {
	return domain.User{
		Username:    d.Username,
		Email:       d.Email,
		Password:    d.Password,
		ProfileData: d.ProfileData,
		Age:         d.Age,
	}
}
