package requests

type PinLoginRequest struct {
	Email string `json:"email" binding:"required,email,min=6,max=254"`
	Pin   string `json:"pin" binding:"required,len=4,numeric"`
}
