package requests

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
)

type CreateIdentityRequest struct {
	Email    string     `json:"email" binding:"required,email,min=6,max=254"`
	Password string     `json:"password" binding:"required,min=9,max=128"`
	PIN      string     `json:"pin" binding:"omitempty,numeric,len=4"`
	Role     enums.Role `json:"role" binding:"required,oneof=admin family_member primary_relative patient healthcare_professional"`
}
