package auth

import (
	"encoding/json"
	"log"
	"net/http"

	jwt "github.com/davidwin93/authentication/pkg/jwt"

	"golang.org/x/oauth2"
)

/*
Need to handle authentication via the following methods:
* username and password
* google auth

# This will be done by exporting a set of http handlers that can handle the entire Oauth flow, and accept username and password

I need the following interfaces:
* LoginValidation confirms if a username and password are valid
* PasswordHardener is used to harden a password before it is stored
* SocialValidation confirms that a user is signed up and is called on each callback
*/
type User struct {
	Name string
}
type LoginValidation interface {
	// IsUserPasswordValid returns true if the username and password are valid. If an error is returned a generic error will be sent to the client
	GetUserIfPasswordValid(username, password string) (*User, error)
}

type SocialClaim struct {
	Username string `json:"username"`
}
type SocialValidation interface {
	IsUserValid(*SocialClaim) (bool, error)
}

type PasswordHardener interface {
	// HardenPassword takes a password and returns a salt and a hardened password. If an error is returned a generic error will be sent to the client
	HardenPassword(password string) (string, error)
}

type AuthenticationService struct {
	UserPasswordValidator LoginValidation
	SocialValidator       SocialValidation
	Oauth2Config          *oauth2.Config
	Oauth2Secret          string
	JWTHandler            *jwt.JWTHandler
	RedirectURL           string
}

func NewAuthenticationService(configs ...AuthenticationConfig) *AuthenticationService {

	empty := &AuthenticationService{}
	for _, config := range configs {
		empty = config(empty)
	}
	return empty
}

type UserPasswordData struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

func (auth *AuthenticationService) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if auth.UserPasswordValidator == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userPassword := UserPasswordData{}

	switch r.Header.Get("Content-Type") {
	case "application/json":
		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(&userPassword)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	case "application/x-www-form-urlencoded":
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		userPassword.Username = r.Form.Get("username")
		userPassword.Password = r.Form.Get("password")
		if userPassword.Username == "" || userPassword.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := auth.UserPasswordValidator.GetUserIfPasswordValid(userPassword.Username, userPassword.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user != nil {
		auth.JWTHandler.InjectJWTKey(jwt.JWTOptions{Username: userPassword.Username, Name: user.Name}, w, r)
		http.Redirect(w, r, auth.RedirectURL, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)

}

func (auth *AuthenticationService) ValidateUser(w http.ResponseWriter, r *http.Request) {
	jwtValue := ""
	cookie, err := r.Cookie("token")
	if err == nil {
		jwtValue = cookie.Value
	}
	token := r.Header.Get("Authorization")
	if token != "" {
		jwtValue = token
	}

	if jwtValue == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// if err := cookie.Valid(); err != nil {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	return
	// }
	claims, err := auth.JWTHandler.ValidateJWT(jwtValue)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	socialClaim := &SocialClaim{
		Username: claims.Username,
	}
	err = json.NewEncoder(w).Encode(socialClaim)
	if err != nil {
		log.Println(err)
	}
}
