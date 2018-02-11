package auth

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/banzaicloud/banzai-types/database"
	"github.com/banzaicloud/pipeline/cloud"
	jwt "github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/gin-gonic/gin"
	"github.com/qor/auth"
	"github.com/qor/auth/authority"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/github"
	"github.com/qor/redirect_back"
	"github.com/qor/session/manager"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"

	banzaiConstants "github.com/banzaicloud/banzai-types/constants"
	banzaiUtils "github.com/banzaicloud/banzai-types/utils"
)

const ApiIssuer = "https://banzaicloud.com/"
const DroneSessionCookie = "user_sess"
const DroneSessionCookieType = "sess"
const DroneUserCookieType = "user"

var ApiAudiences = []string{"https://pipeline.banzaicloud.com"}

//ApiGroup is grouping name for the token
var ApiGroup = "ApiGroup"

// Init authorization
var (
	RedirectBack *redirect_back.RedirectBack

	Auth *auth.Auth

	Authority *authority.Authority

	authEnabled      bool
	signingKeyBase64 []byte
	signingKeyBase32 string
	tokenStore       TokenStore
)

type ScopedClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
	// Drone
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
}

type DroneClaims struct {
	*claims.Claims
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
}

func IsEnabled() bool {
	return authEnabled
}

func lookupAccessToken(userId, token string) (bool, error) {
	return tokenStore.Lookup(userId, token)
}

func validateAccessToken(claims *ScopedClaims) (bool, error) {
	userID := claims.Subject
	tokenID := claims.Id
	return lookupAccessToken(userID, tokenID)
}

func Init() {
	authEnabled = viper.GetBool("dev.authenabled")
	if !authEnabled {
		banzaiUtils.LogInfo(banzaiConstants.TagAuth, "Authentication is disabled.")
		return
	}

	signingKey := viper.GetString("dev.tokensigningkey")
	if signingKey == "" {
		panic("Token signing key is missing from configuration")
	}
	signingKeyBase64, _ = base64.URLEncoding.DecodeString(signingKey)
	signingKeyBase32 = base32.StdEncoding.EncodeToString([]byte(signingKey))

	RedirectBack = redirect_back.New(&redirect_back.Config{
		SessionManager:  manager.SessionManager,
		IgnoredPrefixes: []string{"/auth"},
	})

	// Initialize Auth with configuration
	Auth = auth.New(&auth.Config{
		DB:         database.DB(),
		Redirector: auth.Redirector{RedirectBack},
		UserModel:  User{},
		UserStorer: BanzaiUserStorer{signingKeyBase32: signingKeyBase32, droneDB: initDroneDatabase()},
		ViewPaths:  []string{"github.com/banzaicloud/pipeline/views"},
		SessionStorer: &BanzaiSessionStorer{auth.SessionStorer{
			SessionName:    "_auth_session",
			SessionManager: manager.SessionManager,
			SigningMethod:  jwt.SigningMethodHS256,
			SignedString:   signingKeyBase32,
		}},
	})

	githubProvider := github.New(&github.Config{
		// ClientID and ClientSecret is validated inside github.New()
		ClientID:     viper.GetString("dev.clientid"),
		ClientSecret: viper.GetString("dev.clientsecret"),

		// The same as Drone's scopes
		Scopes: []string{
			"repo",
			"repo:status",
			"user:email",
			"read:org",
		},
	})
	githubProvider.AuthorizeHandler = NewGithubAuthorizeHandler(githubProvider)
	Auth.RegisterProvider(githubProvider)

	Authority = authority.New(&authority.Config{
		Auth: Auth,
	})

	tokenStore = NewVaultTokenStore()
}

// TODO: it should be possible to generate tokens via a token (not just session cookie)
func GenerateToken(c *gin.Context) {
	currentUser := getCurrentUser(c.Request)
	if currentUser == nil {
		err := c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session"))
		banzaiUtils.LogInfo(banzaiConstants.TagAuth, c.ClientIP(), err.Error())
		return
	}

	tokenID := uuid.NewV4().String()

	// Create the Claims
	claims := &ScopedClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    ApiIssuer,
			Audience:  ApiAudiences[0],
			IssuedAt:  jwt.TimeFunc().Unix(),
			ExpiresAt: 0,
			Subject:   strconv.Itoa(int(currentUser.ID)),
			Id:        tokenID,
		},
		Scope: "api:invoke",        // "scope" for Pipeline
		Type:  DroneUserCookieType, // "type" for Drone
		Text:  currentUser.Login,   // "text" for Drone
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(signingKeyBase32))

	if err != nil {
		err = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to sign token: %s", err))
		banzaiUtils.LogInfo(banzaiConstants.TagAuth, c.ClientIP(), err.Error())
	} else {
		err = tokenStore.Store(strconv.Itoa(int(currentUser.ID)), tokenID)
		if err != nil {
			err = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to store token: %s", err))
			banzaiUtils.LogInfo(banzaiConstants.TagAuth, c.ClientIP(), err.Error())
		} else {
			c.JSON(http.StatusOK, gin.H{"token": signedToken})
		}
	}
}

func hmacKeyFunc(token *jwt.Token) (interface{}, error) {
	// Don't forget to validate the alg is what you expect:
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Method.Alg())
	}
	return []byte(signingKeyBase32), nil
}

//Auth0Handler handler for Gin
func Auth0Handler(c *gin.Context) {
	currentUser := Auth.GetCurrentUser(c.Request)
	if currentUser != nil {
		return
	}

	claims := ScopedClaims{}
	accessToken, err := jwtRequest.ParseFromRequestWithClaims(c.Request, jwtRequest.OAuth2Extractor, &claims, hmacKeyFunc)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			cloud.JsonKeyError: "Invalid token",
		})
		banzaiUtils.LogInfo(banzaiConstants.TagAuth, "Invalid token:", err)
		return
	}

	isTokenValid, err := validateAccessToken(&claims)
	if err != nil || !accessToken.Valid || !isTokenValid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			cloud.JsonKeyError: "Invalid token",
		})
		banzaiUtils.LogInfo(banzaiConstants.TagAuth, "Invalid token:", err)
		return
	}

	hasScope := strings.Contains(claims.Scope, "api:invoke")

	// TODO: metadata and group check for later hardening
	/**
	metadata, okMetadata := claims["scope"].(map[string]interface{})
	authorization, okAuthorization := metadata["authorization"].(map[string]interface{})
	groups, hasGroups := authorization["groups"].([]interface{})
	**/

	if !hasScope {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			cloud.JsonKeyError: "Needs more privileges",
		})
		banzaiUtils.LogInfo(banzaiConstants.TagAuth, "Needs more privileges")
		return
	}
	c.Next()
}

type BanzaiSessionStorer struct {
	auth.SessionStorer
}

func (sessionStorer *BanzaiSessionStorer) Update(w http.ResponseWriter, req *http.Request, claims *claims.Claims) error {
	token := sessionStorer.SignedToken(claims)
	err := sessionStorer.SessionManager.Add(w, req, sessionStorer.SessionName, token)
	if err != nil {
		return err
	}

	// Set the drone cookie as well
	currentUser := getCurrentUser(req)
	if currentUser == nil {
		return fmt.Errorf("Can't get current user")
	}
	droneClaims := &DroneClaims{Claims: claims, Type: DroneSessionCookieType, Text: currentUser.Login}
	tokenToken := sessionStorer.SignedTokenWithDrone(droneClaims)
	SetCookie(w, req, DroneSessionCookie, tokenToken)
	return nil
}

// SignedToken generate signed token with Claims
func (sessionStorer *BanzaiSessionStorer) SignedTokenWithDrone(claims *DroneClaims) string {
	token := jwt.NewWithClaims(sessionStorer.SigningMethod, claims)
	println("secret:", sessionStorer.SignedString)
	signedToken, _ := token.SignedString([]byte(sessionStorer.SignedString))
	return signedToken
}
