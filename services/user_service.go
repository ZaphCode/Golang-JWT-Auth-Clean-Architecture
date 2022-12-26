package services

import (
	"fmt"
	"time"

	"github.com/ZaphCode/auth-jwt-app/domain"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//* Constructor
func NewUserService(repo domain.UserRepository) domain.UserService {
	return &userServiceImpl{repo: repo}
}

//* Implementation
type userServiceImpl struct {
	repo domain.UserRepository
}

func (s *userServiceImpl) Create(user *domain.User) error {
	if user, err := s.repo.FindByEmail(user.Email); user != nil || err == nil {
		return fmt.Errorf("email taken")
	}

	ID, err := uuid.NewUUID()

	if err != nil {
		return fmt.Errorf("uuid.NewUUID: %w", err)
	}

	user.ID = ID

	user.CreatedAt = time.Now().Unix()

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		return fmt.Errorf("bycrypt.GenPass: %w", err)
	}

	user.Password = string(hash)

	user.Role = "user"

	if user.ProfileData == nil {
		user.ProfileData = []byte("{}")
	}

	if err := s.repo.Save(user); err != nil {
		return fmt.Errorf("repo.Save(): %w", err)
	}

	user.Password = ""

	return nil
}

func (s *userServiceImpl) GetAll() ([]domain.User, error) {
	return s.repo.FindAll()
}

func (s *userServiceImpl) GetByID(ID uuid.UUID) (*domain.User, error) {
	return s.repo.FindByID(ID)
}

func (s *userServiceImpl) GetByEmail(email string) (*domain.User, error) {
	return s.repo.FindByEmail(email)
}

func (s *userServiceImpl) Delete(ID uuid.UUID) error {
	return s.repo.Remove(ID)
}
