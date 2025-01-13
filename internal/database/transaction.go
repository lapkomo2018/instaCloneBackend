package database

import (
	"database/sql"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

type Transaction struct {
	*gorm.DB
}

func (tx *Transaction) EnsureRollback() {
	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	if err := tx.Rollback().Error; err != nil {
		if !errors.Is(err, sql.ErrTxDone) {
			panic(fmt.Sprintf("failed to rollback transaction: %v", err))
		}
	}
}
