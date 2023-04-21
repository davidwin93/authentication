package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BcryptPasswordHandler(t *testing.T) {
	b := &BcryptPasswordHandler{}
	hashedPass, err := b.HardenPassword("password")
	assert.Nil(t, err)
	assert.NotEmpty(t, hashedPass)
	isValid, err := b.IsPasswordValid(hashedPass, "password")
	assert.True(t, isValid)
	assert.Nil(t, err)
	isValid, err = b.IsPasswordValid(hashedPass, "password2")
	assert.False(t, isValid)
	assert.NotNil(t, err)
}
