package user

import (
	"database/sql"
	"fmt"
	"log"
	"time"

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

	// Query the database
	rows, err := s.db.Query("SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		log.Printf("Database query error: %v", err) // Log any query errors
		return nil, err
	}
	defer rows.Close() // Ensure rows are closed after use

	// Check if there is at least one row
	if !rows.Next() {
		log.Printf("No user found with email: %s", email) // Log if no user is found
		return nil, nil                                   // Return nil user and nil error
	}

	// Scan the row into the User struct
	u, err := scanRowIntoUser(rows)
	if err != nil {
		log.Printf("Error scanning row into user: %v", err) // Log scanning errors
		return nil, err
	}

	// Check for errors during row iteration
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
		&user.Otp,
		&user.OtpExpiry,
		&user.Verified,
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
	_, err := s.db.Exec(`INSERT INTO users ("firstName", "lastName", email, password, otp, otp_expiry, verified) VALUES ($1, $2, $3, $4, $5, $6, $7)`, user.FirstName, user.LastName, user.Email, user.Password, user.Otp, user.OtpExpiry, user.Verified)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) MarkUserAsVerified(userID string) error {
	query := `UPDATE users SET verified = TRUE WHERE id = $1`
	_, err := s.db.Exec(query, userID)
	return err
}

func (s *Store) UpdateUserOTP(userID string, otp string, otpExpiry time.Time) error {
	query := `UPDATE users SET otp = $1, otp_expiry = $2 WHERE id = $3`
	_, err := s.db.Exec(query, otp, otpExpiry, userID)
	return err
}

func (s *Store) UpdatePassword(userID string, hashedPassword string) error {
	query := `UPDATE users SET password = $1, "updatedAt" = CURRENT_TIMESTAMP WHERE id = $2`
	_, err := s.db.Exec(query, hashedPassword, userID)
	return err
}
