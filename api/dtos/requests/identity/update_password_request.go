package requests

type UpdatePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required,min=9,max=128"`
	NewPassword string `json:"newPassword" binding:"required,min=9,max=128,nefield=OldPassword"` // nefield ensures new password is different
}
