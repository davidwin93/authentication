package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	util "github.com/davidwin93/authentication/pkg/util"
	"github.com/stretchr/testify/assert"
)

func Test_JWTHandlerCreation(t *testing.T) {

	private, public := util.GenerateRSAPair()

	handler := NewJWTHandlerBytes(private, public)
	assert.NotNil(t, handler)
}
func Test_JWTInjection(t *testing.T) {

	private, public := util.GenerateRSAPair()

	handler := NewJWTHandlerBytes(private, public)
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	handler.InjectJWTKey("david", r, req)
	if r.Result().StatusCode != http.StatusOK {
		t.Error("Failed to inject JWT key")
	}
	request := &http.Request{Header: http.Header{"Cookie": []string{r.Header().Get("Set-Cookie")}}}
	cookie, err := request.Cookie("token")
	assert.Nil(t, err)
	if cookie.Value == "" {
		t.Error("expected jwt cookie to be set")
	}

	claims, err := handler.ValidateJWT(cookie.Value)
	assert.Equal(t, "david", claims.Username)
	assert.Nil(t, err)
}
