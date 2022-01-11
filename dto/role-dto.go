package dto

type RoleDTO struct {
	Name      string `json:"name" validate:"required,min=4,max=15"`
	Uuid      int    `json:"uuid"`
	IsDeleted bool   `json:"is_deleted"`
}
