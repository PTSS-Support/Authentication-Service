package requests

type PinCreateRequest struct {
	Pin string `json:"pin" binding:"required,len=4,numeric"`
}
