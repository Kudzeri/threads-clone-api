package middleware

import (
	"github.com/Kudzeri/threads-clone-api/utils"
	"github.com/gofiber/fiber/v2"
)

func JWTProtected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authorization header"})
		}
		// Извлекаем токен (ожидается формат "Bearer <token>")
		tokenStr := authHeader[len("Bearer "):]
		_, err := utils.ValidateJWT(tokenStr)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		return c.Next()
	}
}
