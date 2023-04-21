package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/davidwin93/authentication/pkg/jwt"
	util "github.com/davidwin93/authentication/pkg/util"
	"github.com/stretchr/testify/assert"
)

func Test_NewAuthentication(t *testing.T) {
	auth := NewAuthenticationService()
	assert.Nil(t, auth.UserPasswordValidator)
	assert.Nil(t, auth.SocialValidator)
}

type TestSocialValidator struct{}

func (t *TestSocialValidator) IsUserValid(*SocialClaim) (bool, error) {
	return true, nil
}

type TestUserPasswordValidator struct {
	PasswordValidator func(username, password string) (bool, error)
}

func (t *TestUserPasswordValidator) IsUserPasswordValid(username, password string) (bool, error) {
	return t.PasswordValidator(username, password)
}
func Test_NewAuthenticationWithSocialValidator(t *testing.T) {
	auth := NewAuthenticationService(WithSocialValidator(&TestSocialValidator{}))
	assert.Nil(t, auth.UserPasswordValidator)
	assert.NotNil(t, auth.SocialValidator)
}

func Test_NewAuthenticationMultipleConfigs(t *testing.T) {
	auth := NewAuthenticationService(WithSocialValidator(&TestSocialValidator{}), func(as *AuthenticationService) *AuthenticationService {
		as.UserPasswordValidator = &TestUserPasswordValidator{}
		return as
	})
	assert.NotNil(t, auth.UserPasswordValidator)
	assert.NotNil(t, auth.SocialValidator)
}

func Test_LoginHandler(t *testing.T) {
	auth := NewAuthenticationService(WithSocialValidator(&TestSocialValidator{}), func(as *AuthenticationService) *AuthenticationService {
		as.UserPasswordValidator = &TestUserPasswordValidator{
			PasswordValidator: func(username, password string) (bool, error) {
				return true, nil
			},
		}
		return as
	})
	privateKey, publicKey := util.GenerateRSAPair()

	auth.JWTHandler = jwt.NewJWTHandlerBytes([]byte(privateKey), []byte(publicKey))

	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	auth.LoginHandler(r, req)
	if r.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("Status code returned, %d, did not match expected code %d", r.Result().StatusCode, http.StatusBadRequest)
	}
	jsonData := map[string]string{"username": "test", "password": "test"}
	data, err := json.Marshal(&jsonData)
	if err != nil {
		t.Error(err)
	}

	r = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/login", bytes.NewBuffer(data))
	req.Header.Add("content-type", "application/json")
	auth.LoginHandler(r, req)

	if r.Result().StatusCode != http.StatusFound {
		t.Errorf("Status code returned, %d, did not match expected code %d", r.Result().StatusCode, http.StatusFound)
	}

	r = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/login", nil)
	req.Header.Add("content-type", "application/json")
	auth.LoginHandler(r, req)
	if r.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("Status code returned, %d, did not match expected code %d", r.Result().StatusCode, http.StatusBadRequest)
	}
	auth.UserPasswordValidator = &TestUserPasswordValidator{
		PasswordValidator: func(username, password string) (bool, error) {
			return false, fmt.Errorf("test error")
		},
	}
	r = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/login", bytes.NewBuffer(data))
	req.Header.Add("content-type", "application/json")
	auth.LoginHandler(r, req)
	if r.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("Status code returned, %d, did not match expected code %d", r.Result().StatusCode, http.StatusInternalServerError)
	}

}

func Test_ValidateUser(t *testing.T) {
	private, public := util.GenerateRSAPair()
	handler := jwt.NewJWTHandlerBytes(private, public)
	auth := NewAuthenticationService(WithUserPasswordValidator(&TestUserPasswordValidator{}))
	auth.JWTHandler = handler
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	handler.InjectJWTKey("david", r, req)
	if r.Result().StatusCode != http.StatusOK {
		t.Error("Failed to inject JWT key")
	}
	request := &http.Request{Header: http.Header{"Cookie": []string{r.Header().Get("Set-Cookie")}}}
	r = httptest.NewRecorder()
	auth.ValidateUser(r, request)
	assert.Equal(t, http.StatusOK, r.Result().StatusCode)
}
