package responses

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
)

type IdentityResponse struct {
	ID    string     `json:"id" binding:"required,uuid"`
	Email string     `json:"email" binding:"required,email,min=6,max=254"`
	Role  enums.Role `json:"role" binding:"required,oneof=admin family_member primary_relative patient healthcare_professional"`
}
