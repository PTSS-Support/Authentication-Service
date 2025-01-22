package requests

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
)

type CreateIdentityRequest struct {
	UserId    string     `json:"userId" binding:"required,uuid"`
	Email     string     `json:"email" binding:"required,email,min=6,max=254"`
	Password  string     `json:"password" binding:"required,min=8,max=128"`
	Role      enums.Role `json:"role" binding:"required,oneof=ADMIN FAMILY_MEMBER PRIMARY_RELATIVE PATIENT HEALTHCARE_PROFESSIONAL"`
	GroupID   string     `json:"groupId" binding:"omitempty,uuid"`
	FirstName string     `json:"firstName" binding:"required"`
	LastName  string     `json:"lastName" binding:"required"`
}
