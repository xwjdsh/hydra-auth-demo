package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	wraphh "github.com/turtlemonvh/gin-wraphh"
)

type handler struct {
	hydraAdmin   *client.OryHydra
	hydraPublic  *client.OryHydra
	oAuth2Client *models.OAuth2Client
	r            *gin.Engine
}

func initHandler(adminUrl, publicUrl string) (*handler, error) {
	adminURL, err := url.Parse(adminUrl)
	if err != nil {
		return nil, err
	}

	hydraAdmin := client.NewHTTPClientWithConfig(nil,
		&client.TransportConfig{
			Schemes:  []string{adminURL.Scheme},
			Host:     adminURL.Host,
			BasePath: adminURL.Path,
		},
	)

	publicURL, err := url.Parse(publicUrl)
	if err != nil {
		return nil, err
	}
	hydraPublic := client.NewHTTPClientWithConfig(nil,
		&client.TransportConfig{
			Schemes:  []string{publicURL.Scheme},
			Host:     publicURL.Host,
			BasePath: publicURL.Path,
		},
	)

	hydraAdmin.Admin.DeleteOAuth2Client(
		admin.NewDeleteOAuth2ClientParams().WithID("auth-demo"),
	)

	_, err = hydraAdmin.Admin.CreateOAuth2Client(
		admin.NewCreateOAuth2ClientParams().WithBody(&models.OAuth2Client{
			ClientID:     "auth-demo",
			ClientSecret: "auth-demo",
			RedirectUris: []string{"http://127.0.0.1:9000/callback"},
			Scope:        "user product order admin",
		}))
	if err != nil {
		return nil, err
	}

	r := gin.Default()
	h := &handler{
		hydraAdmin:  hydraAdmin,
		hydraPublic: hydraPublic,
		r:           r,
	}

	csrfMw := csrf.Protect(
		[]byte("csrc-key"),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.Secure(false),
	)
	r.Use(wraphh.WrapHH(csrfMw))

	r.LoadHTMLGlob("templates/*")
	r.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	r.GET("/login", h.loginPage)

	r.GET("/callback", h.callback)
	r.GET("/consent", h.consentPage)

	r.POST("/login", h.login)
	r.POST("/consent", h.consent)

	return h, nil
}

func main() {
	h, err := initHandler(os.Getenv("HYDRA_ADMIN_URL"), os.Getenv("HYDRA_PUBLIC_URL"))
	if err != nil {
		log.Panicf("err: %v\n", err)
	}

	h.r.Run(":9000")
}

func (h *handler) login(c *gin.Context) {
	var req struct {
		Username string `form:"username"`
		Password string `form:"password"`
	}
	if err := c.Bind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	if req.Username != "auth-demo" || req.Password != "auth-demo" {
		c.String(http.StatusUnauthorized, "username or password error")
		return
	}

	loginChallenge := c.Query("login_challenge")
	if loginChallenge == "" {
		c.String(http.StatusUnauthorized, "login_challenge is empty")
		return
	}

	_, err := h.hydraAdmin.Admin.GetLoginRequest(
		admin.NewGetLoginRequestParams().WithLoginChallenge(loginChallenge),
	)
	if err != nil {
		c.String(http.StatusUnauthorized, "login_challenge is empty")
		return
	}

	username := req.Username
	resp, err := h.hydraAdmin.Admin.AcceptLoginRequest(
		admin.NewAcceptLoginRequestParams().WithBody(&models.AcceptLoginRequest{
			Remember: true,
			Subject:  &username,
		}).WithLoginChallenge(loginChallenge),
	)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Redirect(http.StatusFound, *resp.Payload.RedirectTo)
}

func (h *handler) consentPage(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Redirect(http.StatusFound, "/index")
		return
	}

	resp, err := h.hydraAdmin.Admin.GetConsentRequest(
		admin.NewGetConsentRequestParams().WithConsentChallenge(challenge),
	)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.HTML(http.StatusOK, "consent.html", gin.H{
		"ClientID":         resp.Payload.Client.ClientID,
		"RequestedScope":   resp.Payload.RequestedScope,
		"ConsentChallenge": challenge,
	})
}

func (h *handler) consent(c *gin.Context) {
	consent := c.Query("consent_challenge")
	if consent == "" {
		c.Status(http.StatusInternalServerError)
		return
	}

	resp, err := h.hydraAdmin.Admin.AcceptConsentRequest(
		admin.NewAcceptConsentRequestParams().WithBody(&models.AcceptConsentRequest{
			GrantScope: c.Request.Form["scope"],
			Remember:   true,
		}),
	)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Redirect(http.StatusFound, *resp.Payload.RedirectTo)
}

func (h *handler) callback(c *gin.Context) {
	c.String(http.StatusOK, "callback")
}

func (h *handler) loginPage(c *gin.Context) {
	challenge := c.Query("login_challenge")
	c.HTML(http.StatusOK, "login.html", gin.H{
		"LoginChallenge": challenge,
		csrf.TemplateTag: csrf.TemplateField(c.Request),
	})
}
