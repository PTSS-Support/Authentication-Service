package responses

import "time"

type CreateIdentityResponse struct {
	ID       string    `json:"id" binding:"required,uuid"`
	Username string    `json:"username"`
	Created  time.Time `json:"created,omitempty" format:"date-time"`
}
