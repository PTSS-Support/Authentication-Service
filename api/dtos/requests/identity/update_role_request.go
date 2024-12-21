package requests

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
)

type UpdateRoleRequest struct {
	Role enums.Role `json:"role" binding:"required,oneof=admin family_member primary_relative patient healthcare_professional"`
}
