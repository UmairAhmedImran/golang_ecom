package types

type UserStore interface {
  GetUserByEmail(email string) (*User, error)
  GetUserByID(id int) (*User, error)
  CreateUser(User) error
} 

type User struct {
  ID          int64   `json:"id"`
  FirstName   string `json:"firstName"`
  LastName    string  `json:"lastName"`
  Email       string `json:"email"`
  Password    string`json:"-"`
  CreatedAt string `json:"createdAt"`
}

type RegisterUserPayload struct {
  FirstName   string `json:"firstName"`
  LastName    string  `json:"lastName"`
  Email       string `json:"email"`
  Password    string`json:"password"`
}
