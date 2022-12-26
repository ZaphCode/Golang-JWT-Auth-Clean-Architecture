package api

type SuccessResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Detail  any    `json:"detail"`
}
