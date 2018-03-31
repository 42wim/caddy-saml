package samlplugin

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"log"
)

type DB struct {
	*gorm.DB
}

func NewDB(uri string) *DB {
	if uri == "" {
		return nil
	}
	fmt.Println("Opening the connection to the database...")
	uri = uri + "?charset=utf8&parseTime=True&loc=Local"
	db, err := gorm.Open("mysql", uri)
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&Session{})
	d := &DB{db}
	return d
}
