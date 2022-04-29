package samlidp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// User represents a stored user. The data here are used to
// populate user once the user has authenticated.
type User struct {
	Name              string   `json:"name"`
	PlaintextPassword *string  `json:"password,omitempty"` // not stored
	HashedPassword    []byte   `json:"hashed_password,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Email             string   `json:"email,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	Surname           string   `json:"surname,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	ScopedAffiliation string   `json:"scoped_affiliation,omitempty"`
}

// HandleListUsers handles the `GET /users/` request and responds with a JSON formatted list
// of user names.
func (s *Server) HandleListUsers(ctx *gin.Context) {
	users, err := s.Store.List(ctx, "/users/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(ctx.Writer).Encode(struct {
		Users []string `json:"users"`
	}{Users: users})
}

// HandleGetUser handles the `GET /users/:id` request and responds with the user object in JSON
// format. The HashedPassword field is excluded.
func (s *Server) HandleGetUser(ctx *gin.Context) {
	user := User{}
	err := s.Store.Get(ctx, fmt.Sprintf("/users/%s", ctx.Param("id")), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	user.HashedPassword = nil
	json.NewEncoder(ctx.Writer).Encode(user)
}

// HandlePutUser handles the `PATCH /users/:id` request. It accepts a JSON formatted user object in
// the request body and stores it. If the PlaintextPassword field is present then it is hashed
// and stored in HashedPassword. If the PlaintextPassword field is not present then
// HashedPassword retains it's stored value.
func (s *Server) HandlePutUser(ctx *gin.Context) {
	user := User{}
	if err := json.NewDecoder(ctx.Request.Body).Decode(&user); err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	user.Name = ctx.Param("id")

	if user.PlaintextPassword != nil {
		var err error
		user.HashedPassword, err = bcrypt.GenerateFromPassword([]byte(*user.PlaintextPassword), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Printf("ERROR: %s", err)
			http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		existingUser := User{}
		err := s.Store.Get(ctx, fmt.Sprintf("/users/%s", ctx.Param("id")), &existingUser)
		switch {
		case err == nil:
			user.HashedPassword = existingUser.HashedPassword
		case err == ErrNotFound:
			// nop
		default:
			s.logger.Printf("ERROR: %s", err)
			http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
	user.PlaintextPassword = nil

	err := s.Store.Put(ctx, fmt.Sprintf("/users/%s", ctx.Param("id")), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx.Writer.WriteHeader(http.StatusNoContent)
}

// HandleDeleteUser handles the `DELETE /users/:id` request.
func (s *Server) HandleDeleteUser(ctx *gin.Context) {
	err := s.Store.Delete(ctx, fmt.Sprintf("/users/%s", ctx.Param("id")))
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx.Writer.WriteHeader(http.StatusNoContent)
}
