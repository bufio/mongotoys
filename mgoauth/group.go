package mgoauth

import (
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure/membership"
	"labix.org/v2/mgo/bson"
)

type Group struct {
	Id               bson.ObjectId `bson:"_id"`
	membership.Group `bson:",inline"`
}

func (g *Group) GetId() model.Identifier {
	return mtoy.ID{g.Id}
}

func (g *Group) SetId(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		if !bson.IsObjectIdHex(tid.Encode()) {
			return membership.ErrInvalidId
		} else {
			g.Id = bson.ObjectIdHex(tid.Encode())
			return nil
		}
	}
	g.Id = tid.ObjectId
	return nil
}
