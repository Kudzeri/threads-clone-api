package handler

import (
	"context"

	"github.com/Kudzeri/threads-clone-api/usecase"
	"github.com/gofiber/fiber/v2"
)

// RegisterRequest представляет данные для регистрации пользователя.
// swagger:model RegisterRequest
type RegisterRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"password123"`
}

// LoginRequest представляет данные для авторизации пользователя.
// swagger:model LoginRequest
type LoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"password123"`
}

// TokenResponse представляет ответ с JWT токеном.
// swagger:model TokenResponse
type TokenResponse struct {
	Token string `json:"token" example:"jwt_token_placeholder"`
}

// ErrorResponse представляет сообщение об ошибке.
// swagger:model ErrorResponse
type ErrorResponse struct {
	Error string `json:"error" example:"error message"`
}

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
// @Tags Auth
// @Accept json
// @Produce json
// @Param user body RegisterRequest true "User data"
// @Success 200 {object} TokenResponse "JWT token response"
// @Failure 400 {object} ErrorResponse "Invalid request or error during registration"
// @Router /register [post]
func (h *UserHandler) Register(c *fiber.Ctx) error {
	req := new(RegisterRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	user, err := h.userUsecase.RegisterUser(context.Background(), req.Email, req.Password)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	token, err := GenerateJWTForUser(user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}
	return c.JSON(fiber.Map{"token": token})
}

// Login godoc
// @Summary Login user
// @Description Authenticate user and return JWT
// @Tags Auth
// @Accept json
// @Produce json
// @Param user body LoginRequest true "User credentials"
// @Success 200 {object} TokenResponse "JWT token response"
// @Failure 400 {object} ErrorResponse "Invalid credentials or request"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Router /login [post]
func (h *UserHandler) Login(c *fiber.Ctx) error {
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
func GenerateJWTForUser(userID int) (string, error) {
	// Здесь должна быть ваша логика генерации JWT.
	return "jwt_token_placeholder", nil
}
