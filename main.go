package main

import (
	"context"
	"log"
	"os"

	"github.com/Kudzeri/threads-clone-api/config"
	"github.com/Kudzeri/threads-clone-api/handler"
	"github.com/Kudzeri/threads-clone-api/middleware"
	"github.com/Kudzeri/threads-clone-api/repository"
	"github.com/Kudzeri/threads-clone-api/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Загрузка конфигурации
	cfg := config.LoadConfig()
	
	// Инициализация подключения к PostgreSQL
	dbpool, err := pgxpool.Connect(context.Background(), cfg.DBUrl)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer dbpool.Close()

	// Инициализация репозитория и бизнес-логики
	userRepo := repository.NewUserRepository(dbpool)
	userUsecase := usecase.NewUserUsecase(userRepo)
	userHandler := handler.NewUserHandler(userUsecase)

	// Конфигурация OAuth для Google
	googleOAuthConfig := &oauth2.Config{
		ClientID:     cfg.OAuthGoogleConfig.ClientID,
		ClientSecret: cfg.OAuthGoogleConfig.ClientSecret,
		RedirectURL:  cfg.OAuthGoogleConfig.RedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	// Конфигурация OAuth для VK
	vkOAuthConfig := &oauth2.Config{
		ClientID:     cfg.OAuthVKConfig.ClientID,
		ClientSecret: cfg.OAuthVKConfig.ClientSecret,
		RedirectURL:  cfg.OAuthVKConfig.RedirectURL,
		Scopes:       []string{"email"}, // проверьте необходимые разрешения
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://oauth.vk.com/authorize",
			TokenURL: "https://oauth.vk.com/access_token",
		},
	}

	// Инициализация OAuth-обработчика с настройками для Google, VK и Telegram
	oauthHandler := handler.NewOAuthHandler(googleOAuthConfig, vkOAuthConfig, cfg.TelegramConfig)

	// Инициализация Fiber
	app := fiber.New()

	// Маршрут для Swagger-документации
	app.Get("/swagger/*", swagger.HandlerDefault)

	// Публичные маршруты
	app.Post("/register", userHandler.Register)
	app.Post("/login", userHandler.Login)
	app.Get("/auth/:provider", oauthHandler.AuthRedirect)
	app.Get("/auth/:provider/callback", oauthHandler.AuthCallback)

	// Пример защищённого маршрута
	app.Get("/protected", middleware.JWTProtected(), func(c *fiber.Ctx) error {
		return c.SendString("Protected content")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
