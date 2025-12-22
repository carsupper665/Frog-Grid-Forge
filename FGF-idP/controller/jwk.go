package controller

import (
	"FGF-idP/model"

	"github.com/gin-gonic/gin"
)

type DiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                          string   `json:"jwks_uri"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	// …其他想加的
}

func buildDiscoveryResponse(meta *model.JakMetadata) *DiscoveryResponse {
	return &DiscoveryResponse{
		Issuer:                meta.Issuer,
		AuthorizationEndpoint: meta.AuthorizationEndpoint,
		TokenEndpoint:         meta.TokenEndpoint,
		UserinfoEndpoint:      meta.UserinfoEndpoint,
		JwksURI:               meta.JwksURI,
		EndSessionEndpoint:    meta.EndSessionEndpoint,

		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
	}
}

func JwksMetadata(c *gin.Context) {
	metadata, err := model.GetDiscovery()
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Failed to get OIDC metadata",
		})
		return
	}

	c.JSON(200, buildDiscoveryResponse(metadata))

}

func JwksKeys(c *gin.Context) {
	jwks, err := model.GetActiveKeys()
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Failed to	get JWKS keys",
		})
		return
	}

	c.JSON(200, jwks)
}

func GetKeysBySid(c *gin.Context) {
	sid := c.Param("sid")
	jwk, err := model.GetKeyBySid(sid)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Failed to	get JWKS key by sid",
		})
		return
	}

	c.JSON(200, jwk)
}
