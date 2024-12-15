package enums

type Role string

const (
	RoleAdmin                  Role = "admin"
	RoleFamilyMember           Role = "family_member"
	RolePrimaryRelative        Role = "primary_relative"
	RolePatient                Role = "patient"
	RoleHealthcareProfessional Role = "healthcare_professional"
)

// IsValid checks if the role is one of the defined constants
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleFamilyMember, RolePrimaryRelative, RolePatient, RoleHealthcareProfessional:
		return true
	}
	return false
}
