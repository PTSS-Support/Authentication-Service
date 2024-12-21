package requests

type CreatePINRequest struct {
	PIN string `json:"pin" binding:"required,len=4"`
}
