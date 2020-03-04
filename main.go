package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func main() {

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	router := gin.Default()
	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	router.Use(ginzap.RecoveryWithZap(logger, true))

	oauth2Config, verifier := newOAuthConfig(logger)

	accessHandler := NewAccessHandler(logger, oauth2Config, verifier, os.Getenv("CALLBACK_STATUS_STRING"))

	authRouter := router.Group("/auth")
	{
		authRouter.GET("/login/web", accessHandler.WebLogin)
		authRouter.GET("/callback", accessHandler.Callback)

	}
	port := ":" + os.Getenv("SECURITY_APP_PORT")
	router.Run(port)
}

func newOAuthConfig(logger *zap.Logger) (oauth2.Config, *oidc.IDTokenVerifier) {
	configURL := os.Getenv("KEYCLOAK_URL")
	clientID := os.Getenv("KEYCLOAK_CLIENTID")
	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	redirectURL := os.Getenv("SECURITY_APP_HOST") + ":" + os.Getenv("SECURITY_APP_PORT") + "/auth/callback"

	provider, e := oidc.NewProvider(context.Background(), configURL)

	if e != nil {
		logger.Panic("OIDC Provider not ready", zap.String("error", e.Error()))
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier := provider.Verifier(oidcConfig)

	return oauth2Config, verifier
}

// AccessHandler expose all the methods for handling keycloak communications
type AccessHandler interface {
	WebLogin(c *gin.Context)
	Callback(c *gin.Context)
	Logout(c *gin.Context)
}

type accessHandler struct {
	logger       *zap.Logger
	oauth2Config oauth2.Config
	state        string
	verifier     *oidc.IDTokenVerifier
}

// NewAccessHandler generates a new instance of accessHandler
func NewAccessHandler(logger *zap.Logger, oauth2Config oauth2.Config, verifier *oidc.IDTokenVerifier, state string) AccessHandler {
	return &accessHandler{
		logger:       logger,
		oauth2Config: oauth2Config,
		state:        state,
		verifier:     verifier,
	}
}

func (h *accessHandler) WebLogin(c *gin.Context) {
	rawAccessToken := c.GetHeader("Authorization")

	if rawAccessToken == "" {
		c.Redirect(http.StatusFound, h.oauth2Config.AuthCodeURL(h.state))
		return
	}

	parts := strings.Split(rawAccessToken, " ")
	if len(parts) != 2 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	_, err := h.verifier.Verify(context.Background(), parts[1])

	if err != nil {
		c.Redirect(http.StatusFound, h.oauth2Config.AuthCodeURL(h.state))
		return
	}
}

func (h *accessHandler) Callback(c *gin.Context) {
	if c.Query("state") != h.state {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"Error": "state did not match"})
		return
	}

	oauth2Token, e := h.oauth2Config.Exchange(context.Background(), c.Query("code"))
	if e != nil {
		c.AbortWithError(http.StatusInternalServerError, e)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"Error": "No id_token field in oauth2 token."})
		return
	}
	idToken, err := h.verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"Error": "Failed to verify ID Token"})
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		c.AbortWithError(http.StatusInternalServerError, e)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, e)
		return
	}
	c.JSON(http.StatusOK, data)
}

func (h *accessHandler) Logout(c *gin.Context) {

}
