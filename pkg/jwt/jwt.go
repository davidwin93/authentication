package auth

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type JWTHandler struct {
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
}

func NewJWTHandler(privateKey, publicKey string) *JWTHandler {
	jwtHandler := &JWTHandler{}
	signBytes, err := ioutil.ReadFile(privateKey)
	if err != nil {
		return nil
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil
	}

	jwtHandler.signKey = signKey

	verifyBytes, err := ioutil.ReadFile(publicKey)
	if err != nil {
		return nil
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil
	}
	jwtHandler.verifyKey = verifyKey
	return jwtHandler
}

func NewJWTHandlerBytes(privateKey, publicKey []byte) *JWTHandler {
	jwtHandler := &JWTHandler{}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil
	}

	jwtHandler.signKey = signKey

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil
	}
	jwtHandler.verifyKey = verifyKey
	return jwtHandler
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var algo jwt.SigningMethod = jwt.SigningMethodRS256

func (jwtHandler *JWTHandler) InjectJWTKey(username string, w http.ResponseWriter, req *http.Request) {
	expirationTime := time.Now().Add(5 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(algo, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtHandler.signKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		MaxAge:   300,
		HttpOnly: true,
	})
}

func (jwtHandler *JWTHandler) ValidateJWT(data string) (*Claims, error) {
	claims := Claims{}
	token, err := jwt.ParseWithClaims(data, &claims, func(token *jwt.Token) (interface{}, error) {
		return jwtHandler.verifyKey, nil
	})
	if err != nil {
		return nil, err
	}
	if token.Method.Alg() != algo.Alg() {
		return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
	}
	if token.Valid {
		return &claims, nil
	}
	return nil, fmt.Errorf("invalid jwt")

}
