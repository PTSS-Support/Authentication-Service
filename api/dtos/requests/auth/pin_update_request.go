package requests

type PinUpdateRequest struct {
	OldPin string `json:"oldPin" binding:"required,len=4,numeric"`
	NewPin string `json:"newPin" binding:"required,len=4,numeric"`
}
