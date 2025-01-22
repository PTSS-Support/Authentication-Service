package requests

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
)

type UpdateRoleRequest struct {
	Role enums.Role `json:"role" binding:"required,oneof=ADMIN FAMILY_MEMBER PRIMARY_RELATIVE PATIENT HEALTHCARE_PROFESSIONAL"`
}
