package server

import (
	"io/fs"

	"github.com/Soup9x/Lake-Effect-Bouy/db"
)

func mustSub() fs.FS {
	sub, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}
