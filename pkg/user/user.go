package user

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/user"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var Store = NewUserManager(&user.Users{})

type User struct {
	Username string
	Password string
}

func (u *User) OnePassword() string {
	hash, err := blake2b.New512([]byte(u.Password))
	if err != nil {
		return ""
	}

	hash.Write([]byte(u.Username))
	hash.Write([]byte(".yuh@1in_s@lt_u2er-"))
	hash.Write([]byte(u.Username))

	return hex.EncodeToString(hash.Sum(nil))
}

type UserManager struct {
	mu          sync.Mutex
	onePassword syncmap.SyncMap[string, *User]
	user        syncmap.SyncMap[string, *User]
}

func NewUserManager(us *user.Users) *UserManager {
	u := &UserManager{}

	for _, v := range us.GetUsers() {
		user := User{
			Username: v.GetName(),
			Password: v.GetPassword(),
		}

		u.user.Store(user.Username, &user)
		u.onePassword.Store(user.OnePassword(), &user)
	}

	return u
}

func (u *UserManager) Save(user *user.User) (*User, error) {
	if user.GetName() == "" || user.GetPassword() == "" {
		return nil, fmt.Errorf("invalid username or password")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	ou, ok := u.user.Load(user.GetName())
	if ok {
		u.onePassword.Delete(ou.OnePassword())
		u.user.Delete(user.GetName())
	}

	nu := User{
		Username: user.GetName(),
		Password: user.GetPassword(),
	}

	u.onePassword.Store(nu.OnePassword(), &nu)
	u.user.Store(nu.Username, &nu)

	return &nu, nil
}

func (u *UserManager) Delete(user string) error {
	if user == "" {
		return fmt.Errorf("invalid username")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	ou, ok := u.user.Load(user)
	if ok {
		u.onePassword.Delete(ou.OnePassword())
		u.user.Delete(user)
	}

	return nil
}

func (u *UserManager) List() *user.Users {
	uu := user.Users_builder{}

	for value := range u.user.RangeValues {
		uu.Users = append(uu.Users, user.User_builder{
			Name:        proto.String(value.Username),
			Password:    proto.String(value.Password),
			OnePassword: proto.String(value.OnePassword()),
		}.Build())
	}

	return uu.Build()
}

func (u *UserManager) VerifyOnePassword(op string) (string, bool) {
	ou, ok := u.onePassword.Load(op)
	if !ok {
		return "", false
	}

	return ou.Username, true
}

func (u *UserManager) VerifyUserPass(user, pass string) (string, bool) {
	ou, ok := u.user.Load(user)
	if !ok {
		return "", false
	}

	if subtle.ConstantTimeCompare([]byte(ou.Password), []byte(pass)) != 1 {
		return "", false
	}

	return ou.Username, true
}

type userApi struct {
	user.UnimplementedUsersServer
	um *UserManager
	db config.DB
}

func NewUserApi(db config.DB) *userApi {
	u := &userApi{
		um: Store,
		db: db,
	}

	_ = db.View(func(s *config.Setting) error {
		for _, v := range s.GetUsers().GetUsers() {
			if _, err := u.um.Save(v); err != nil {
				log.Warn("save user failed", "err", err)
			}
		}

		return nil
	})

	return u
}

func (u *userApi) Add(ctx context.Context, user *user.User) (*user.User, error) {
	err := u.db.Batch(func(s *config.Setting) error {
		_, err := u.um.Save(user)
		if err != nil {
			return err
		}

		s.GetUsers().GetUsers()[user.GetName()] = user
		return nil
	})

	return user, err
}
func (u *userApi) List(context.Context, *emptypb.Empty) (*user.Users, error) {
	return u.um.List(), nil
}

func (u *userApi) Delete(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := u.db.Batch(func(s *config.Setting) error {
		if err := u.um.Delete(req.GetValue()); err != nil {
			return err
		}

		delete(s.GetUsers().GetUsers(), req.GetValue())
		return nil
	})

	return &emptypb.Empty{}, err
}
