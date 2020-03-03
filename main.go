package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var logger *zap.Logger
var oauth2Config oauth2.Config
var provider *oidc.Provider
var verifier *oidc.IDTokenVerifier
var state string = "onestate"

func init() {

	logger, _ = zap.NewDevelopment()
	defer logger.Sync()

	var e error

	configURL := "http://localhost:8080/auth/realms/develop"

	provider, e = oidc.NewProvider(context.Background(), configURL)

	if e != nil {
		logger.Panic("OIDC Provider not ready", zap.String("error", e.Error()))
	}

	clientID := "web"
	clientSecret := "781cda7d-28af-4a3a-a8e5-2cc30905b8db"

	redirectURL := "http://localhost:8181/auth/callback"

	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier = provider.Verifier(oidcConfig)

}

func main() {

	router := gin.Default()
	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	router.Use(ginzap.RecoveryWithZap(logger, true))

	accessHandler := NewAccessHandler(logger, oauth2Config)

	authRouter := router.Group("/auth")
	{
		authRouter.GET("/login/web", accessHandler.WebLogin)
		authRouter.GET("/callback", accessHandler.Callback)

	}

	router.Run(":8181")
}

type AccessHandler interface {
	WebLogin(c *gin.Context)
	Callback(c *gin.Context)
	Logout(c *gin.Context)
}

type accessHandler struct {
	logger       *zap.Logger
	oauth2Config oauth2.Config
}

func NewAccessHandler(logger *zap.Logger, oauth2Config oauth2.Config) AccessHandler {
	return &accessHandler{logger: logger, oauth2Config: oauth2Config}
}

func (h *accessHandler) WebLogin(c *gin.Context) {
	rawAccessToken := c.GetHeader("Authorization")

	if rawAccessToken == "" {
		c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL(state))
		return
	}

	parts := strings.Split(rawAccessToken, " ")
	if len(parts) != 2 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	_, err := verifier.Verify(context.Background(), parts[1])

	if err != nil {
		c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL(state))
		return
	}
}

func (h *accessHandler) Callback(c *gin.Context) {
	if c.Query("state") != state {
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
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
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
