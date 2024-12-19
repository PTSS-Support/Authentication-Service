package requests

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email,min=6,max=254"`
	Password string `json:"password" binding:"required,min=9,max=128"`
}
