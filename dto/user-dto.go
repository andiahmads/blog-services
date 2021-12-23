package dto

// type RegisterDTO struct {
// 	Name     string `json:"name" form:"name" binding:"required"`
// 	Email    string `json:"email" form:"email" binding:"required,email" validate:"email"`
// 	Password string `json:"password" form:"password" binding:"required"`
// }

type RegisterDTO struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required"`
}

type VerificationEmail struct {
	ID       uint64 `json:"id"`
	IsActive bool   `json:"is_active"`
}

type CekStatus struct {
	ID       uint64 `json:"id"`
	IsActive bool   `json:"is_active"`
}
