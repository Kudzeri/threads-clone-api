package handler

import (
	"context"

	"github.com/Kudzeri/threads-clone-api/usecase"
	"github.com/gofiber/fiber/v2"
)

// UserHandler отвечает за обработку запросов, связанных с пользователями.
type UserHandler struct {
	userUsecase usecase.UserUsecase
}

// NewUserHandler создаёт новый экземпляр UserHandler.
func NewUserHandler(u usecase.UserUsecase) *UserHandler {
	return &UserHandler{
		userUsecase: u,
	}
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterRequest true "User data"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Router /register [post]
func (h *UserHandler) Register(c *fiber.Ctx) error {
	type RegisterRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	req := new(RegisterRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	user, err := h.userUsecase.RegisterUser(context.Background(), req.Email, req.Password)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	token, err := GenerateJWTForUser(user.ID) // Например, вызов утилиты для JWT
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}
	return c.JSON(fiber.Map{"token": token})
}

// Login godoc
// @Summary Login user
// @Description Authenticate user and return JWT
// @Tags auth
// @Accept json
// @Produce json
// @Param user body LoginRequest true "User credentials"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Router /login [post]
func (h *UserHandler) Login(c *fiber.Ctx) error {
	type LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	req := new(LoginRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	user, err := h.userUsecase.AuthenticateUser(context.Background(), req.Email, req.Password)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	token, err := GenerateJWTForUser(user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}
	return c.JSON(fiber.Map{"token": token})
}

// GenerateJWTForUser — вспомогательная функция для генерации JWT токена для пользователя.
// Реализуйте её согласно вашей логике (например, вызов utils.GenerateJWT).
func GenerateJWTForUser(userID int) (string, error) {
	// Пример: return utils.GenerateJWT(userID)
	return "jwt_token_placeholder", nil
}
