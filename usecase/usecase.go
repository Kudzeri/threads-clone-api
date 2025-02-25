package usecase

import (
	"context"
	"errors"

	"github.com/Kudzeri/threads-clone-api/models"
	"github.com/Kudzeri/threads-clone-api/repository"
	"golang.org/x/crypto/bcrypt"
)

type UserUsecase interface {
	RegisterUser(ctx context.Context, email, password string) (*models.User, error)
	AuthenticateUser(ctx context.Context, email, password string) (*models.User, error)
}

type userUsecase struct {
	userRepo repository.UserRepository
}

func NewUserUsecase(repo repository.UserRepository) UserUsecase {
	return &userUsecase{
		userRepo: repo,
	}
}

func (u *userUsecase) RegisterUser(ctx context.Context, email, password string) (*models.User, error) {
	if email == "" || password == "" {
		return nil, errors.New("invalid data")
	}
	// Хэширование пароля
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user := &models.User{
		Email:    email,
		Password: string(hashed),
	}
	err = u.userRepo.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *userUsecase) AuthenticateUser(ctx context.Context, email, password string) (*models.User, error) {
	user, err := u.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	return user, nil
}
