package requests

type UpdatePINRequest struct {
	OldPIN string `json:"old_pin" binding:"required,numeric,len=4"`
	NewPIN string `json:"new_pin" binding:"required,numeric,len=4,nefield=OldPIN"` // nefield ensures new PIN is different
}
