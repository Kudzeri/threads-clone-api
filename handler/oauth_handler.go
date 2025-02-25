package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Kudzeri/threads-clone-api/config"
	"github.com/Kudzeri/threads-clone-api/utils"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// OAuthHandler содержит конфигурацию OAuth для разных провайдеров
type OAuthHandler struct {
	GoogleConfig   *oauth2.Config
	VKConfig       *oauth2.Config
	TelegramConfig *config.TelegramConfig
}

// NewOAuthHandler создает новый экземпляр OAuthHandler с конфигурациями для Google, VK и Telegram
func NewOAuthHandler(googleConfig, vkConfig *oauth2.Config, telegramConfig *config.TelegramConfig) *OAuthHandler {
	return &OAuthHandler{
		GoogleConfig:   googleConfig,
		VKConfig:       vkConfig,
		TelegramConfig: telegramConfig,
	}
}

// AuthRedirect godoc
// @Summary OAuth Redirect
// @Description Redirect to OAuth provider for authentication
// @Tags auth
// @Param provider path string true "OAuth provider"
// @Success 302 {string} string "redirect"
// @Router /auth/{provider} [get]
func (h *OAuthHandler) AuthRedirect(c *fiber.Ctx) error {
	provider := c.Params("provider")
	var authURL string
	switch provider {
	case "google":
		authURL = h.GoogleConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	case "vk":
		authURL = h.VKConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	case "telegram":
		// Telegram Login Widget реализуется на стороне клиента, поэтому редирект не требуется.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Telegram login is handled on the client side using the Telegram Login Widget"})
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported provider"})
	}
	return c.Redirect(authURL)
}

// AuthCallback godoc
// @Summary OAuth Callback
// @Description Handle OAuth provider callback
// @Tags auth
// @Param provider path string true "OAuth provider"
// @Param code query string false "Authorization code (not used for Telegram)"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Router /auth/{provider}/callback [get]
func (h *OAuthHandler) AuthCallback(c *fiber.Ctx) error {
	provider := c.Params("provider")
	switch provider {
	case "google":
		return h.handleGoogleCallback(c)
	case "vk":
		return h.handleVKCallback(c)
	case "telegram":
		return h.handleTelegramCallback(c)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported provider"})
	}
}

// ---------------- Google Callback ----------------

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func getGoogleUserInfo(token *oauth2.Token) (*GoogleUserInfo, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get user info from Google")
	}
	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func (h *OAuthHandler) handleGoogleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}
	token, err := h.GoogleConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "failed to exchange token: " + err.Error()})
	}

	userInfo, err := getGoogleUserInfo(token)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "failed to get Google user info: " + err.Error()})
	}
	if userInfo.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email not provided by Google"})
	}

	// Поиск или создание пользователя по email
	userID, err := getOrCreateUser("google", userInfo.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to process user: " + err.Error()})
	}

	jwtToken, err := utils.GenerateJWT(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate JWT"})
	}
	return c.JSON(fiber.Map{"token": jwtToken, "oauth_token": token})
}

// ---------------- VK Callback ----------------

type VKUserInfo struct {
	Response []struct {
		ID        int    `json:"id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	} `json:"response"`
}

func getVKUserInfo(token *oauth2.Token) (*VKUserInfo, error) {
	resp, err := http.Get("https://api.vk.com/method/users.get?access_token=" + token.AccessToken + "&v=5.131")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get user info from VK")
	}
	var userInfo VKUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func (h *OAuthHandler) handleVKCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}
	token, err := h.VKConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "failed to exchange token: " + err.Error()})
	}

	// Если scope email запрошен, VK возвращает его вместе с токеном
	email, _ := token.Extra("email").(string)
	if email == "" {
		// Если email не передан, пытаемся получить информацию через API
		vkUser, err := getVKUserInfo(token)
		if err != nil || len(vkUser.Response) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "failed to get VK user info"})
		}
		// Формируем фиктивный email на основе VK id
		email = "vk_user_" + strconv.Itoa(vkUser.Response[0].ID) + "@vk.com"
	}

	// Поиск или создание пользователя по email
	userID, err := getOrCreateUser("vk", email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to process user: " + err.Error()})
	}

	jwtToken, err := utils.GenerateJWT(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate JWT"})
	}
	return c.JSON(fiber.Map{"token": jwtToken, "oauth_token": token})
}

// ---------------- Telegram Callback ----------------

func (h *OAuthHandler) handleTelegramCallback(c *fiber.Ctx) error {
	// Telegram Login Widget передает данные через GET-параметры, включая хэш для проверки подлинности.
	idStr := c.Query("id")
	authDate := c.Query("auth_date")
	hash := c.Query("hash")
	// Дополнительные параметры: first_name, last_name, username, photo_url

	if idStr == "" || authDate == "" || hash == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing telegram auth parameters"})
	}

	// Валидация данных по алгоритму Telegram
	if !validateTelegramAuth(c, h.TelegramConfig.BotToken) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid telegram auth data"})
	}

	telegramID, err := strconv.Atoi(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid telegram id"})
	}

	// Формирование фиктивного email на основе Telegram id, т.к. email обычно не передается
	email := "telegram_" + strconv.Itoa(telegramID) + "@telegram.com"

	// Поиск или создание пользователя по email
	userID, err := getOrCreateUser("telegram", email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to process user: " + err.Error()})
	}

	jwtToken, err := utils.GenerateJWT(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate JWT"})
	}
	return c.JSON(fiber.Map{"token": jwtToken})
}

// ---------------- Вспомогательные функции ----------------

// validateTelegramAuth проверяет целостность данных, полученных от Telegram Login Widget.
func validateTelegramAuth(c *fiber.Ctx, botToken string) bool {
	// Список ключей, которые будут использоваться для формирования строки проверки
	keys := []string{"auth_date", "first_name", "id", "last_name", "photo_url", "username"}
	var dataCheckArr []string
	for _, key := range keys {
		val := c.Query(key)
		if val != "" {
			dataCheckArr = append(dataCheckArr, key+"="+val)
		}
	}
	// Сортируем массив по возрастанию
	sort.Strings(dataCheckArr)
	dataCheckString := strings.Join(dataCheckArr, "\n")

	// Вычисляем секретный ключ: SHA256 от botToken
	secretKey := sha256.Sum256([]byte(botToken))

	// Вычисляем HMAC-SHA256 от dataCheckString с использованием secretKey
	hmacHash := hmac.New(sha256.New, secretKey[:])
	hmacHash.Write([]byte(dataCheckString))
	computedHash := hex.EncodeToString(hmacHash.Sum(nil))

	providedHash := c.Query("hash")
	return computedHash == providedHash
}

// getOrCreateUser имитирует поиск или создание пользователя на основе provider и email.
// В реальном приложении эта логика должна быть реализована через соответствующий usecase или репозиторий.
func getOrCreateUser(provider, email string) (int, error) {
	_ = provider
	if email == "" {
		return 0, errors.New("email is empty")
	}
	// Для демонстрации возвращаем "уникальный" id, вычисленный по сумме символов email.
	var sum int
	for _, c := range email {
		sum += int(c)
	}
	return sum, nil
}
