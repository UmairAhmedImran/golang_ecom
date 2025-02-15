package user

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/UmairAhmedImran/ecom/types"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetUserByEmail(email string) (*types.User, error) {
	log.Printf("Querying database for email: %s", email) // Log the email being queried
	rows, err := s.db.Query("SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		log.Printf("Database query error: %v", err) // Log any query errors
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		log.Printf("No user found for email: %s", email) // Log if no user is found
		return nil, fmt.Errorf("user not found")
	}

	u := new(types.User)
	// Scan the row into the User struct
	u, err = scanRowIntoUser(rows)
	if err != nil {
		log.Printf("Error scanning row into user: %v", err) // Log scanning errors
		return nil, err
	}

	if err := rows.Err(); err != nil {
		log.Printf("Row iteration error: %v", err) // Log row iteration errors
		return nil, err
	}

	log.Printf("User found: %+v", u) // Log the user details
	return u, nil
}
func scanRowIntoUser(rows *sql.Rows) (*types.User, error) {
	user := new(types.User)
	err := rows.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Store) GetUserByID(id int) (*types.User, error) {
	rows, err := s.db.Query("SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, err
	}

	u := new(types.User)
	for rows.Next() {
		u, err = scanRowIntoUser(rows)
		if err != nil {
			return nil, err
		}
	}
	if u.ID == "" {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

func (s *Store) CreateUser(user types.User) error {
	_, err := s.db.Exec(`INSERT INTO users ("firstName", "lastName", email, password) VALUES ($1, $2, $3, $4)`, user.FirstName, user.LastName, user.Email, user.Password)
	if err != nil {
		return err
	}
	return nil
}
