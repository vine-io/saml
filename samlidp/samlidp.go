// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/vine-io/saml"
	"github.com/vine-io/saml/logger"
)

// Options represent the parameters to New() for creating a new IDP server
type Options struct {
	URL         url.URL
	Key         crypto.PrivateKey
	Logger      logger.Interface
	Certificate *x509.Certificate
	Store       Store
}

// Server represents an IDP server. The server provides the following URLs:
//
//     /metadata     - the SAML metadata
//     /sso          - the SAML endpoint to initiate an authentication flow
//     /login        - prompt for a username and password if no session established
//     /login/:shortcut - kick off an IDP-initiated authentication flow
//     /services     - RESTful interface to Service objects
//     /users        - RESTful interface to User objects
//     /sessions     - RESTful interface to Session objects
//     /shortcuts    - RESTful interface to Shortcut objects
type Server struct {
	http.Handler
	idpConfigMu      sync.RWMutex // protects calls into the IDP
	logger           logger.Interface
	serviceProviders map[string]*saml.EntityDescriptor
	IDP              saml.IdentityProvider // the underlying IDP
	Store            Store                 // the data store
}

// New returns a new Server
func New(opts Options) (*Server, error) {
	metadataURL := opts.URL
	metadataURL.Path = metadataURL.Path + "/metadata"
	ssoURL := opts.URL
	ssoURL.Path = ssoURL.Path + "/sso"
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	s := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		IDP: saml.IdentityProvider{
			Key:         opts.Key,
			Logger:      logr,
			Certificate: opts.Certificate,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
		},
		logger: logr,
		Store:  opts.Store,
	}

	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if err := s.initializeServices(); err != nil {
		return nil, err
	}
	s.InitializeHTTP()
	return s, nil
}

// InitializeHTTP sets up the HTTP handler for the server. (This function
// is called automatically for you by New, but you may need to call it
// yourself if you don't create the object using New.)
func (s *Server) InitializeHTTP() {
	mux := gin.New()
	s.Handler = mux

	mux.Any("/metadata", func(ctx *gin.Context) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeMetadata(ctx.Writer, ctx.Request)
	})
	mux.Any("/sso", func(ctx *gin.Context) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeSSO(ctx.Writer, ctx.Request)
	})

	mux.Any("/login", s.HandleLogin)
	mux.Any("/login/:shortcut", s.HandleIDPInitiated)
	mux.POST("/login/:shortcut/:state", s.HandleIDPInitiated)

	mux.GET("/services/", s.HandleListServices)
	mux.GET("/services/:id", s.HandleGetService)
	mux.PATCH("/services/:id", s.HandlePutService)
	mux.POST("/services/:id", s.HandlePutService)
	mux.DELETE("/services/:id", s.HandleDeleteService)

	mux.GET("/users/", s.HandleListUsers)
	mux.GET("/users/:id", s.HandleGetUser)
	mux.PATCH("/users/:id", s.HandlePutUser)
	mux.DELETE("/users/:id", s.HandleDeleteUser)

	mux.GET("/sessions/", s.HandleListSessions)
	mux.GET("/sessions/:id", s.HandleGetSession)
	mux.DELETE("/sessions/:id", s.HandleDeleteSession)

	mux.GET("/shortcuts/", s.HandleListShortcuts)
	mux.GET("/shortcuts/:id", s.HandleGetShortcut)
	mux.PATCH("/shortcuts/:id", s.HandlePutShortcut)
	mux.DELETE("/shortcuts/:id", s.HandleDeleteShortcut)
}
