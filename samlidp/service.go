package samlidp

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vine-io/saml"
)

// Service represents a configured SP for whom this IDP provides authentication services.
type Service struct {
	// Name is the name of the service provider
	Name string

	// Metdata is the XML metadata of the service provider.
	Metadata saml.EntityDescriptor
}

// GetServiceProvider returns the Service Provider metadata for the
// service provider ID, which is typically the service provider's
// metadata URL. If an appropriate service provider cannot be found then
// the returned error must be os.ErrNotExist.
func (s *Server) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	s.idpConfigMu.RLock()
	defer s.idpConfigMu.RUnlock()
	rv, ok := s.serviceProviders[serviceProviderID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return rv, nil
}

// HandleListServices handles the `GET /services/` request and responds with a JSON formatted list
// of service names.
func (s *Server) HandleListServices(ctx *gin.Context) {
	services, err := s.Store.List(ctx, "/services/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(ctx.Writer).Encode(struct {
		Services []string `json:"services"`
	}{Services: services})
}

// HandleGetService handles the `GET /services/:id` request and responds with the service
// metadata in XML format.
func (s *Server) HandleGetService(ctx *gin.Context) {
	service := Service{}
	err := s.Store.Get(ctx, fmt.Sprintf("/services/%s", ctx.Param("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	xml.NewEncoder(ctx.Writer).Encode(service.Metadata)
}

// HandlePutService handles the `PATCH /shortcuts/:id` request. It accepts the XML-formatted
// service metadata in the request body and stores it.
func (s *Server) HandlePutService(ctx *gin.Context) {
	service := Service{}

	metadata, err := getSPMetadata(ctx.Request.Body)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	service.Metadata = *metadata

	err = s.Store.Put(ctx, fmt.Sprintf("/services/%s", ctx.Param("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.idpConfigMu.Lock()
	s.serviceProviders[service.Metadata.EntityID] = &service.Metadata
	s.idpConfigMu.Unlock()

	ctx.Writer.WriteHeader(http.StatusNoContent)
}

// HandleDeleteService handles the `DELETE /services/:id` request.
func (s *Server) HandleDeleteService(ctx *gin.Context) {
	service := Service{}
	err := s.Store.Get(ctx, fmt.Sprintf("/services/%s", ctx.Param("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := s.Store.Delete(ctx, fmt.Sprintf("/services/%s", ctx.Param("id"))); err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(ctx.Writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.idpConfigMu.Lock()
	delete(s.serviceProviders, service.Metadata.EntityID)
	s.idpConfigMu.Unlock()

	ctx.Writer.WriteHeader(http.StatusNoContent)
}

// initializeServices reads all the stored services and initializes the underlying
// identity provider to accept them.
func (s *Server) initializeServices() error {
	ctx := context.TODO()
	serviceNames, err := s.Store.List(ctx, "/services/")
	if err != nil {
		return err
	}
	for _, serviceName := range serviceNames {
		service := Service{}
		if err := s.Store.Get(ctx, fmt.Sprintf("/services/%s", serviceName), &service); err != nil {
			return err
		}

		s.idpConfigMu.Lock()
		s.serviceProviders[service.Metadata.EntityID] = &service.Metadata
		s.idpConfigMu.Unlock()
	}
	return nil
}
