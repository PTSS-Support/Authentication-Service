package entities

type TokenIntrospectionResponse struct {
	Active   bool   `json:"active"`
	Exp      int64  `json:"exp"`
	Error    string `json:"error"`
	ErrorMsg string `json:"error_description"`
}
