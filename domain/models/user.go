package models

type User struct {
	ID        string `json:"id" binding:"required,uuid"`
	Email     string `json:"email" binding:"required,email,min=6,max=254"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Role      Role   `json:"role" binding:"required,oneof=admin family_member primary_relative patient healthcare_professional"`
}
