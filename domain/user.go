package domain

import (
	"encoding/json"

	"github.com/google/uuid"
)

type User struct {
	ID          uuid.UUID       `json:"id"`
	Username    string          `json:"username"`
	Email       string          `json:"email"`
	Password    string          `json:"-"`
	Role        string          `json:"role"`
	Age         uint            `json:"age"`
	ProfileData json.RawMessage `json:"profile_data"`
	CreatedAt   int64           `json:"created_at"`
	UpdatedAt   int64           `json:"updated_at"`
}

type UserService interface {
	Create(user *User) error
	GetAll() ([]User, error)
	GetByEmail(email string) (*User, error)
	GetByID(ID uuid.UUID) (*User, error)
	Delete(ID uuid.UUID) error
}

type UserRepository interface {
	Save(user *User) error
	FindAll() ([]User, error)
	FindByEmail(email string) (*User, error)
	FindByID(ID uuid.UUID) (*User, error)
	Remove(ID uuid.UUID) error
	Migrate()
}
