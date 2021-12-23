package dto

type RoleDTO struct {
	Name      string `json:"name" form:"name" binding:"required"`
	Uuid      int    `json:"uuid" form:"uuid"`
	IsDeleted bool   `json:"is_deleted" form:"is_deleted"`
}
