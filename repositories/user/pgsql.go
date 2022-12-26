package user

import (
	"fmt"

	"github.com/ZaphCode/auth-jwt-app/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func NewUserRepository(db gorm.DB) domain.UserRepository {
	return &userRepositoryImpl{db: db}
}

type userRepositoryImpl struct {
	db gorm.DB
}

func (r *userRepositoryImpl) Save(user *domain.User) error {
	return r.db.Create(user).Error
}
func (r *userRepositoryImpl) FindAll() ([]domain.User, error) {
	var users []domain.User

	err := r.db.Find(&users).Error

	if err != nil {
		return nil, err
	}

	return users, nil
}

func (r *userRepositoryImpl) FindByEmail(email string) (*domain.User, error) {
	var user domain.User

	if err := r.db.Where("Email = ?", email).First(&user).Error; err != nil {
		return nil, fmt.Errorf("find user error %w: ", err)
	}

	return &user, nil
}
func (r *userRepositoryImpl) FindByID(ID uuid.UUID) (*domain.User, error) {
	var user domain.User

	if err := r.db.Where("ID = ?", ID).First(&user).Error; err != nil {
		return nil, fmt.Errorf("find user error %w: ", err)
	}

	return &user, nil
}
func (r *userRepositoryImpl) Remove(ID uuid.UUID) error {
	var user domain.User

	if err := r.db.Where("ID = ?", ID).First(&user).Error; err != nil {
		return fmt.Errorf("user not found")
	}

	return r.db.Delete(&user).Error
}
