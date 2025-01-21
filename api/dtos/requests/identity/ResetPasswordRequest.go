package requests

type ResetPasswordRequest struct {
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}
