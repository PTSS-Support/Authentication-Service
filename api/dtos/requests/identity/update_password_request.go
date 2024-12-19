package requests

type UpdatePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required,min=9,max=128"`
	NewPassword string `json:"new_password" binding:"required,min=9,max=128,nefield=OldPassword"` // nefield ensures new password is different
}
