package services

import "github.com/go-playground/validator/v10"

//* Service
type ValidationService interface {
	Validate(any) error
}

//* Constructor
func NewValidationService() ValidationService {
	return &validationServiceImpl{validator: validator.New()}
}

//* Implementation
type validationServiceImpl struct {
	validator *validator.Validate
}

func (s *validationServiceImpl) Validate(data any) error {
	err := s.validator.Struct(data)
	if err != nil {
		var errors ValidationErrors
		for _, err := range err.(validator.ValidationErrors) {
			element := FieldError{err.Field(), s.getErrorMsg(err)}
			errors = append(errors, element)
		}
		return errors
	}
	return nil
}

func (s *validationServiceImpl) getErrorMsg(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "lte":
		return "Should be less than " + fe.Param()
	case "gte":
		return "Should be greater than " + fe.Param()
	case "max":
		return "Should be less than " + fe.Param() + " characters"
	case "min":
		return "Should be greater than " + fe.Param() + " characters"
	case "email":
		return "Invalid email"
	}
	return "Unknown error"
}

type ValidationErrors []FieldError

func (ValidationErrors) Error() string {
	return "someting wentwrong"
}

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}
