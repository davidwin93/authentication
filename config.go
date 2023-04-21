package auth

import jwt "github.com/davidwin93/authentication/pkg/jwt"

type AuthenticationConfig func(*AuthenticationService) *AuthenticationService

func WithSocialValidator(social SocialValidation) AuthenticationConfig {
	return func(as *AuthenticationService) *AuthenticationService {
		as.SocialValidator = social
		return as
	}
}

func WithUserPasswordValidator(userPassword LoginValidation) AuthenticationConfig {
	return func(as *AuthenticationService) *AuthenticationService {
		as.UserPasswordValidator = userPassword
		return as
	}
}

func WithRedirectURL(redirectURL string) AuthenticationConfig {
	return func(as *AuthenticationService) *AuthenticationService {
		as.RedirectURL = redirectURL
		return as
	}
}

func WithJWTKeys(privateKey, publicKey []byte) AuthenticationConfig {
	return func(as *AuthenticationService) *AuthenticationService {
		as.JWTHandler = jwt.NewJWTHandlerBytes(privateKey, publicKey)
		return as
	}
}
