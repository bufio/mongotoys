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
	configfile   string
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
	//a.notifer
	a.pwdHash = sha256.New()
	a.threshold = 15 * time.Minute
	return a
}

func (a *AuthMongoDBCtx) SetPath(p string) {
	a.path = p
}

func (a *AuthMongoDBCtx) SetDomain(d string) {
	a.domain = d
}

func (a *AuthMongoDBCtx) SetOnlineThreshold(t time.Duration) {
	if t > 0 {
		a.threshold = t
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

func (a *AuthMongoDBCtx) GeneratePassword(password string) membership.Password {
	if len(password) == 0 {
		password = secure.RandomString(16)
	}

	pwd := membership.Password{}
	pwd.InitAt = time.Now()
	pwd.Salt = secure.RandomToken(32)
	a.pwdHash.Write([]byte(password))
	a.pwdHash.Write(pwd.Salt)
	pwd.Hashed = a.pwdHash.Sum(nil)
	a.pwdHash.Reset()

	return pwd
}

func (a *AuthMongoDBCtx) createUser(email, password string, app bool) (*Account, error) {
	if !a.fmtChecker.EmailValidate(email) {
		return nil, membership.ErrInvalidEmail
	}
	if !a.fmtChecker.PasswordValidate(password) {
		return nil, membership.ErrInvalidPassword
	}

	u := &Account{}
	u.Id = bson.NewObjectId()
	u.Email = email
	u.Pwd = a.GeneratePassword(password)

	u.Approved = app
	return u, nil
}

func (a *AuthMongoDBCtx) insertUser(u *Account, notif, app bool) error {
	err := a.userColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return membership.ErrDuplicateEmail
		}
		return err
	}

	if notif {
		return a.notifer.AccountAdded(u)
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

	u.Info = *info
	u.Privilege = pri

	return a.insertUser(u, notif, app)
}

func (a *AuthMongoDBCtx) DeleteUser(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if ok && tid.Valid() {
		return a.userColl.RemoveId(tid.ObjectId)
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
	//not Loged-in
	return nil, errors.New("auth: not Loged-in")
}

func (a *AuthMongoDBCtx) FindUser(id model.Identifier) (membership.User, error) {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return nil, membership.ErrInvalidId
	}

	u := &Account{}
	err := a.userColl.FindId(tid.ObjectId).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (a *AuthMongoDBCtx) FindUserByEmail(email string) (membership.User, error) {
	if !a.fmtChecker.EmailValidate(email) {
		return nil, membership.ErrInvalidEmail
	}

	u := &Account{}
	err := a.userColl.Find(bson.M{"email": email}).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (a *AuthMongoDBCtx) findAllUser(offsetKey model.Identifier, limit int, filter bson.M) (membership.UserLister, error) {
	if limit < 0 {
		return nil, nil
	}

	if offsetKey != nil {
		tid, ok := offsetKey.(mtoy.ID)
		if !ok {
			return nil, membership.ErrInvalidId
		} else {
			if filter == nil {
				filter = bson.M{}
			}
			filter["_id"] = bson.M{"$gt": tid.ObjectId}
		}
	}

	var accounts []Account
	if limit > 0 {
		accounts = make([]Account, 0, limit)
	} else {
		accounts = []Account{}
	}

	err := a.userColl.Find(filter).Limit(limit).All(&accounts)
	if err != nil {
		return nil, err
	}

	return &AccountList{Accounts: accounts}, nil
}

func (a *AuthMongoDBCtx) FindAllUser(offsetKey model.Identifier, limit int) (membership.UserLister, error) {
	return a.findAllUser(offsetKey, limit, nil)
}

func (a *AuthMongoDBCtx) FindAllUserOnline(offsetKey model.Identifier, limit int) (membership.UserLister, error) {
	return a.findAllUser(offsetKey, limit, bson.M{"lastactivity": bson.M{"$lt": time.Now().Add(-a.sess.Expiration())}})
}

func (a *AuthMongoDBCtx) CountUserOnline() int {
	n, err := a.userColl.Find(bson.M{"lastactivity": bson.M{
		"$lt": time.Now().Add(-a.sess.Expiration()),
	}}).Count()
	if err == nil {
		return n
	}

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
		return nil, membership.ErrInvalidPassword
	}
	return u, nil
}

func (a *AuthMongoDBCtx) Login(id model.Identifier, remember int) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
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

func (a *AuthMongoDBCtx) Logout() error {
	cookie, err := a.req.Cookie(a.cookieName)
	http.SetCookie(a.respw, &http.Cookie{
		Name:   a.cookieName,
		MaxAge: -1,
	})

	if err == nil {
		//read and parse cookie
		id := cookie.Value[:strings.Index(cookie.Value, "|")]
		if bson.IsObjectIdHex(id) {
			oid := bson.ObjectIdHex(id)
			a.rememberColl.RemoveId(oid)
		}
	}

	a.sess.Delete(a.sessionName)

	return nil
}

func (a *AuthMongoDBCtx) UpdateInfo(id model.Identifier, info *membership.Information, notif bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}
	return a.userColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{"info": info}})
}

func (a *AuthMongoDBCtx) UpdatePrivilege(id model.Identifier, pri map[string]bool, notif bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}
	return a.userColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{"privilege": pri}})
}

func (a *AuthMongoDBCtx) ChangePassword(id model.Identifier, password string, notif bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}

	acc := Account{}
	err := a.userColl.FindId(tid.ObjectId).One(&acc)
	if err != nil {
		return err
	}

	err = a.userColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{
		"oldpwd": acc.GetOldPassword(),
		"pwd":    a.GeneratePassword(password),
	}})
	if err != nil {
		return err
	}

	return a.notifer.PasswordChanged(&acc)
}

func (a *AuthMongoDBCtx) ValidConfirmCode(id model.Identifier, key, code string, regen, del bool) (bool, error) {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return false, membership.ErrInvalidId
	}

	acc := Account{}
	err := a.userColl.FindId(tid.ObjectId).One(&acc)
	if err != nil {
		return false, err
	}

	ok = acc.ConfirmCodes[key] == code
	change := bson.M{}
	if del {
		change["$unset"] = bson.M{"confirmcodes." + key: false}
	} else {
		change["$set"] = bson.M{"confirmcodes." + key: secure.RandomString(32)}
	}

	a.userColl.UpdateId(tid.ObjectId, change)

	return ok, err
}
