package enums

type Role string

const (
	RoleAdmin                  Role = "ADMIN"
	RoleFamilyMember           Role = "FAMILY_MEMBER"
	RolePrimaryRelative        Role = "PRIMARY_RELATIVE"
	RolePatient                Role = "PATIENT"
	RoleHealthcareProfessional Role = "HEALTHCARE_PROFESSIONAL"
)

// IsValid checks if the role is one of the defined constants
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleFamilyMember, RolePrimaryRelative, RolePatient, RoleHealthcareProfessional:
		return true
	}
	return false
}
