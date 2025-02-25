package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Kudzeri/threads-clone-api/models"

	"github.com/jackc/pgx/v4/pgxpool"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
}

type userRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) CreateUser(ctx context.Context, user *models.User) error {
	// Проверка на дублирование email
	var exists bool
	err := r.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", user.Email).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("email already exists")
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	query := `INSERT INTO users (email, password, created_at, updated_at) VALUES ($1, $2, $3, $4) RETURNING id`
	err = r.db.QueryRow(ctx, query, user.Email, user.Password, user.CreatedAt, user.UpdatedAt).Scan(&user.ID)
	return err
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, email, password, created_at, updated_at FROM users WHERE email=$1`
	err := r.db.QueryRow(ctx, query, email).Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}
