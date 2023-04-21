package auth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type googleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
	HD            string `json:"hd"`
}

type GoogleLoginProvider struct {
	config     *oauth2.Config
	stateValue string
}

func (auth *AuthenticationService) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	URL, err := url.Parse(auth.Oauth2Config.Endpoint.AuthURL)
	if err != nil {
		log.Println("Parse: " + err.Error())
	}
	log.Println(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", auth.Oauth2Config.ClientID)
	parameters.Add("scope", strings.Join(auth.Oauth2Config.Scopes, " "))
	parameters.Add("redirect_uri", auth.Oauth2Config.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", auth.Oauth2Secret)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	log.Println(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (auth *AuthenticationService) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Callback-gl..")

	state := r.FormValue("state")
	log.Println(state)
	if state != auth.Oauth2Secret {
		log.Println("invalid oauth state, expected " + auth.Oauth2Secret + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	log.Println(code)

	if code == "" {
		log.Println("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := auth.Oauth2Config.Exchange(context.Background(), code)
		if err != nil {
			log.Println("oauthConfGl.Exchange() failed with " + err.Error() + "\n")
			return
		}
		log.Println("TOKEN>> AccessToken>> " + token.AccessToken)
		log.Println("TOKEN>> Expiration Time>> " + token.Expiry.String())
		log.Println("TOKEN>> RefreshToken>> " + token.RefreshToken)
		resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
		if err != nil {
			log.Println("Get: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()
		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("ReadAll: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		googleUsr := googleUser{}
		err = json.Unmarshal(response, &googleUsr)
		if err != nil {
			log.Println("ReadAll: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		isValid, err := auth.SocialValidator.IsUserValid(&SocialClaim{
			Username: googleUsr.Email,
		})

		if err != nil {
			log.Println("IsUserValid: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		if !isValid {
			log.Println("Invalid: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		auth.JWTHandler.InjectJWTKey(googleUsr.Email, w, r)
		http.Redirect(w, r, auth.RedirectURL, http.StatusFound)
		return
	}
}
