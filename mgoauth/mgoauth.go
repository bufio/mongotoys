// Copyright 2012 The Toys Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package mgoauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure"
	"github.com/kidstuff/toys/secure/membership"
	"github.com/kidstuff/toys/secure/membership/sessions"
	"hash"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"strings"
	"time"
)

type AuthMongoDBCtx struct {
	threshold    time.Duration
	sess         sessions.Provider
	req          *http.Request
	respw        http.ResponseWriter
	notifer      membership.Notificater
	fmtChecker   membership.FormatChecker
	pwdHash      hash.Hash
	userColl     *mgo.Collection
	rememberColl *mgo.Collection
	cookieName   string
	sessionName  string
	path         string
	domain       string
}

var _ membership.Authenticater = &AuthMongoDBCtx{}

func NewAuthDBCtx(w http.ResponseWriter, r *http.Request, sess sessions.Provider,
	userColl, rememberColl *mgo.Collection) *AuthMongoDBCtx {
	a := &AuthMongoDBCtx{}
	a.respw = w
	a.req = r
	a.sess = sess
	a.userColl = userColl
	a.rememberColl = rememberColl
	a.cookieName = "toysAuthCookie"
	a.sessionName = "toysAuthSession"
	a.fmtChecker, _ = membership.NewSimpleChecker(8)
	a.notifer = membership.NewSimpleNotificater()
	a.pwdHash = sha256.New()
	a.threshold = 900 * time.Second
	return a
}

func (a *AuthMongoDBCtx) SetPath(p string) {
	a.path = p
}

func (a *AuthMongoDBCtx) SetDomain(d string) {
	a.domain = d
}

func (a *AuthMongoDBCtx) SetOnlineThreshold(t int) {
	if t > 0 {
		a.threshold = time.Duration(t) * time.Second
	}
}

func (a *AuthMongoDBCtx) SetNotificater(n membership.Notificater) {
	a.notifer = n
}

func (a *AuthMongoDBCtx) SetHashFunc(h hash.Hash) {
	a.pwdHash = h
}

func (a *AuthMongoDBCtx) SetFormatChecker(c membership.FormatChecker) {
	a.fmtChecker = c
}

func (a *AuthMongoDBCtx) createUser(email, password string, app bool) (membership.User, error) {
	if !a.fmtChecker.EmailValidate(email) {
		return nil, membership.ErrInvalidEmail
	}
	if !a.fmtChecker.PasswordValidate(password) {
		return nil, membership.ErrInvalidPassword
	}

	u := &Account{}
	u.Email = email
	u.Pwd.InitAt = time.Now()
	u.Pwd.Salt = secure.RandomToken(32)
	a.pwdHash.Write([]byte(password))
	a.pwdHash.Write(u.Pwd.Salt)
	u.Pwd.Hashed = a.pwdHash.Sum(nil)
	a.pwdHash.Reset()

	u.Approved = app
	return u, nil
}

func (a *AuthMongoDBCtx) insertUser(u membership.User, notif, app bool) error {
	err := a.userColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return membership.ErrDuplicateEmail
		}
		return err
	}

	if notif {
		return a.notifer.AccountAdded(u.GetEmail(), app)
	}
	return nil
}

func (a *AuthMongoDBCtx) AddUser(email, password string, notif, app bool) error {
	u, err := a.createUser(email, password, app)
	if err != nil {
		return err
	}

	return a.insertUser(u, notif, app)
}

func (a *AuthMongoDBCtx) AddUserInfo(email, password string, info *membership.Information,
	pri map[string]bool, notif, app bool) error {
	u, err := a.createUser(email, password, app)
	if err != nil {
		return err
	}

	u.SetInfomation(info)
	u.SetPrivilege(pri)

	return a.insertUser(u, notif, app)
}

func (a *AuthMongoDBCtx) DeleteUser(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if ok && tid.Valid() {
		return a.userColl.RemoveId(tid.ObjectId)
	} else if bson.IsObjectIdHex(id.Encode()) {
		return a.userColl.RemoveId(bson.ObjectIdHex(id.Encode()))
	}
	return membership.ErrInvalidId
}

func (a *AuthMongoDBCtx) GetUser() (membership.User, error) {
	//check for remember cookie
	cookie, err := a.req.Cookie(a.cookieName)
	if err == nil {
		//read and parse cookie
		pos := strings.Index(cookie.Value, "|")
		id := cookie.Value[:pos]
		token := cookie.Value[pos+1:]
		if bson.IsObjectIdHex(id) {
			r := RememberInfo{}
			oid := bson.ObjectIdHex(id)
			//validate
			err = a.rememberColl.FindId(oid).One(&r)
			if err == nil {
				if token == r.Token {
					if r.Exp.Before(time.Now()) {
						//delete expried auth
						goto DelCookie
					}
					user := Account{}
					err = a.userColl.FindId(oid).One(&user)
					if err == nil {
						//re-generate token
						token = base64.URLEncoding.EncodeToString(secure.RandomToken(128))
						http.SetCookie(a.respw, &http.Cookie{
							Name:    a.cookieName,
							Value:   id + "|" + token,
							Expires: r.Exp,
						})
						err = a.rememberColl.UpdateId(oid, bson.M{
							"$set": bson.M{"token": token},
						})
						if err == nil {
							return &user, nil
						}
					}
				}
			}
			a.rememberColl.RemoveId(oid)
		}
	DelCookie:
		http.SetCookie(a.respw, &http.Cookie{
			Name:   a.cookieName,
			MaxAge: -1,
		})
	}
	//check for session
	mapinf, ok := a.sess.Get(a.sessionName).(map[string]interface{})
	if ok {
		var inf SessionInfo
		inf.Id = mapinf["_id"].(mtoy.ID).ObjectId
		inf.At = mapinf["at"].(time.Time)
		if inf.At.Add(a.threshold).After(time.Now()) {
			user := Account{}
			err = a.userColl.FindId(inf.Id).One(&user)
			if err == nil {
				return &user, nil
			}
		} else {
			a.sess.Delete(a.sessionName)
		}
	}
	//not logged-in
	return nil, errors.New("auth: not logged-in")
}

func (a *AuthMongoDBCtx) FindUser(id model.Identifier) (membership.User, error) {
	u := &Account{}
	return u, nil
}

func (a *AuthMongoDBCtx) FindUserByEmail(email string) (membership.User, error) {
	u := &Account{}
	return u, nil
}

func (a *AuthMongoDBCtx) FindAllUser(offsetKey model.Identifier, limit int) ([]membership.User, error) {
	u := []membership.User{}
	return u, nil
}

func (a *AuthMongoDBCtx) FindUserOnline(offsetKey model.Identifier, limit int) ([]membership.User, error) {
	u := []membership.User{}
	return u, nil
}

func (a *AuthMongoDBCtx) CountUserOnline() int {
	return 0
}

func (a *AuthMongoDBCtx) ValidateUser(email string, password string) (membership.User, error) {
	u := &Account{}
	err := a.userColl.Find(bson.M{"email": email}).One(&u)
	if err != nil {
		return nil, err
	}
	a.pwdHash.Write([]byte(password))
	a.pwdHash.Write(u.Pwd.Salt)
	hashed := a.pwdHash.Sum(nil)
	a.pwdHash.Reset()
	if bytes.Compare(u.Pwd.Hashed, hashed) != 0 {
		return nil, err
	}
	return u, nil
}

func (a *AuthMongoDBCtx) LogginUser(id model.Identifier, remember int) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		if !bson.IsObjectIdHex(tid.Encode()) {
			return membership.ErrInvalidId
		} else {
			tid = mtoy.ID{bson.ObjectIdHex(tid.Encode())}
		}
	}

	if remember > 0 {
		//use cookie a rememberColl
		//TODO: change the use of RememberInfo
		r := RememberInfo{}
		r.Id = tid.ObjectId
		r.Exp = time.Now().Add(time.Duration(remember) * time.Second)
		r.Token = base64.URLEncoding.EncodeToString(secure.RandomToken(128))
		http.SetCookie(a.respw, &http.Cookie{
			Name:    a.cookieName,
			Value:   tid.Encode() + "|" + r.Token,
			Expires: r.Exp,
		})
		return a.rememberColl.Insert(&r)
	} else {
		//use session
		s := SessionInfo{}
		s.At = time.Now()
		s.Id = tid.ObjectId
		return a.sess.Set(a.sessionName, s)
	}
	return nil
}
