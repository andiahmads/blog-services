package entity

import (
	"time"
)

type User struct {
	ID           uint64 `gorm:"primary_key:auto_increment" json:"id"`
	UUID         string `gorm:"type:varchar(255)" json:uuid`
	Name         string `gorm:"type:text" json:"name"`
	Email        string `gorm:"unique;type:varchar(255)" json:"email"`
	Avatar       string `gorm:"type:varchar(255)" json:"avatar"`
	Password     string `gorm:"->;<-;not null" json:"-"`
	RoleID       uint64 `gorm:"not null" json:"-"`
	IsActive     bool   `gorm:"not null" json:"is_active"`
	Token        string `gorm:"-" json:"token,omitempty"`
	RefreshToken string `gorm:"-" json:"refresh_token"`
	IsDeleted    bool   `gorm:"type:bool" default:"false"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
