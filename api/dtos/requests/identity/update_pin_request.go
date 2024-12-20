package requests

type UpdatePINRequest struct {
	OldPIN string `json:"oldPin" binding:"required,numeric,len=4"`
	NewPIN string `json:"newPin" binding:"required,numeric,len=4,nefield=OldPIN"` // nefield ensures new PIN is different
}
