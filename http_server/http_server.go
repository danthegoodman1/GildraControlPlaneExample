package http_server

import (
	"context"
	"errors"
	"fmt"
	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/routing"
	"github.com/davecgh/go-spew/spew"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/danthegoodman1/GildraControlPlaneExample/gologger"
	"github.com/danthegoodman1/GildraControlPlaneExample/utils"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
)

var logger = gologger.NewLogger()

type HTTPServer struct {
	Echo *echo.Echo
}

type CustomValidator struct {
	validator *validator.Validate
}

func StartHTTPServer() *HTTPServer {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", utils.GetEnvOrDefault("HTTP_PORT", "8080")))
	if err != nil {
		logger.Error().Err(err).Msg("error creating tcp listener, exiting")
		os.Exit(1)
	}
	s := &HTTPServer{
		Echo: echo.New(),
	}
	s.Echo.HideBanner = true
	s.Echo.HidePort = true
	s.Echo.JSONSerializer = &utils.NoEscapeJSONSerializer{}

	s.Echo.Use(CreateReqContext)
	s.Echo.Use(LoggerMiddleware)
	s.Echo.Use(middleware.CORS())
	s.Echo.Validator = &CustomValidator{validator: validator.New()}

	// technical - no auth
	s.Echo.GET("/hc", s.HealthCheck)
	s.Echo.GET("/", s.Hello)
	s.Echo.POST("/create", ccHandler(s.CreateCert))
	certGroup := s.Echo.Group("/domains/:domain")
	certGroup.GET("/cert", ccHandler(s.GetCert))
	certGroup.GET("/config", ccHandler(s.GetConfig))
	certGroup.GET("/challenge/:token", ccHandler(s.GetTokenKey))

	s.Echo.Listener = listener
	go func() {
		logger.Info().Msg("starting h2c server on " + listener.Addr().String())
		err := s.Echo.StartH2CServer("", &http2.Server{})
		// stop the broker
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("failed to start h2c server, exiting")
			os.Exit(1)
		}
	}()

	return s
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func ValidateRequest(c echo.Context, s interface{}) error {
	if err := c.Bind(s); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(s); err != nil {
		return err
	}
	return nil
}

func (*HTTPServer) HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "ok")
}
func (*HTTPServer) Hello(c echo.Context) error {
	return c.String(http.StatusOK, spew.Sdump(c.Request().Header))
}

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	err := s.Echo.Shutdown(ctx)
	return err
}

func LoggerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		if err := next(c); err != nil {
			// default handler
			c.Error(err)
		}
		stop := time.Since(start)
		// Log otherwise
		logger := zerolog.Ctx(c.Request().Context())
		req := c.Request()
		res := c.Response()

		p := req.URL.Path
		if p == "" {
			p = "/"
		}

		cl := req.Header.Get(echo.HeaderContentLength)
		if cl == "" {
			cl = "0"
		}
		logger.Debug().Str("method", req.Method).Str("remote_ip", c.RealIP()).Str("req_uri", req.RequestURI).Str("handler_path", c.Path()).Str("path", p).Int("status", res.Status).Int64("latency_ns", int64(stop)).Str("protocol", req.Proto).Str("bytes_in", cl).Int64("bytes_out", res.Size).Msg("req recived")
		return nil
	}
}

type CreateCertReq struct {
	Domain   string
	Provider string
}

func (h *HTTPServer) CreateCert(c *CustomContext) error {
	var reqBody CreateCertReq
	if err := ValidateRequest(c, &reqBody); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	var err error
	if reqBody.Provider == "le-staging" || reqBody.Provider == "" {
		log.Println("creating le-staging cert")
		err = createLEStagingCert(c.Request().Context(), reqBody.Domain)
	} else if reqBody.Provider == "zerossl" {
		log.Println("creating zerossl cert")
		err = createZeroSSLCert(c.Request().Context(), reqBody.Domain)
	}
	if err != nil {
		return c.InternalError(err, "error creating cert")
	}
	return c.String(http.StatusOK, "created cert for domain!")
}

type GetCertRes struct {
	Cert string
	Key  string
}

func (h *HTTPServer) GetCert(c *CustomContext) error {
	domain := c.Param("domain")
	if domain == "" {
		return c.String(http.StatusBadRequest, "missing domain query param")
	}

	var res GetCertRes

	certBytes, err := os.ReadFile(fmt.Sprintf("%s.cert", domain))
	if err != nil {
		return c.InternalError(err, "error reading cert")
	}

	keyBytes, err := os.ReadFile(fmt.Sprintf("%s.key", domain))
	if err != nil {
		return c.InternalError(err, "error reading key")
	}

	res.Cert = string(certBytes)
	res.Key = string(keyBytes)

	return c.JSON(http.StatusOK, res)
}

func (h *HTTPServer) GetConfig(c *CustomContext) error {
	domain := c.Param("domain")
	if domain == "" {
		return c.String(http.StatusBadRequest, "missing domain query param")
	}

	res := routing.Config{Rules: []routing.Rule{
		{
			Matches: []routing.Match{
				{
					Destinations: []routing.Destination{
						{
							URL: "http://localhost:8080",
						},
					},
				},
			},
		},
	}}

	return c.JSON(http.StatusOK, res)
}

func (h *HTTPServer) GetTokenKey(c *CustomContext) error {
	token := c.Param("token")
	if token == "" {
		return c.String(http.StatusBadRequest, "missing token query param")
	}

	keyBytes, err := os.ReadFile(path.Join("challenges", token))
	if err != nil {
		return c.InternalError(err, "error reading cert")
	}

	return c.JSON(http.StatusOK, control_plane.ChallengeTokenRes{Key: string(keyBytes)})
}
