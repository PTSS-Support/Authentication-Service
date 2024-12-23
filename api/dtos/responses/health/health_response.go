package requests

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
)

type Check struct {
	Name   string                 `json:"name"`
	Status enums.HealthStatus     `json:"status"`
	Data   map[string]interface{} `json:"data,omitempty"`
}

type HealthResponse struct {
	Status enums.HealthStatus `json:"status"`
	Checks []Check            `json:"checks"`
}
