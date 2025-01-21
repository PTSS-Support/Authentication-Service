package requests

type ValidatePasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}
