package mtoy

import (
	"errors"
	"labix.org/v2/mgo/bson"
)

// ID implements github.com/bufio/toys/model#Identifier
type ID struct {
	bson.ObjectId
}

func NewID() *ID {
	return &ID{bson.NewObjectId()}
}

func (id *ID) Decode(i interface{}) error {
	idStr, ok := i.(string)
	if !ok {
		return errors.New("mongotoys: Decode require a string")
	}

	if !bson.IsObjectIdHex(idStr) {
		return errors.New("mongotoys: Invalid input string format")
	}

	id.ObjectId = bson.ObjectIdHex(idStr)
	return nil
}

func (id *ID) Encode() string {
	return id.Hex()
}
