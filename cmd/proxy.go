package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/go-ldap/ldap"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"gopkg.in/yaml.v3"
)

var config = flag.String("config", "", "path to config file")
var debug = flag.Bool("d", false, "enable debug mode")

type EndPoint struct {
	Name     string
	Uri      string
	BaseDN   string
	BindDN   string
	Password string
	Override bool
}

type Proxy struct {
	BaseDN   string
	BindDN   string
	Password string
}

type ProxyConfig struct {
	Debug     bool
	Proxy     Proxy
	Endpoints []EndPoint
}

func init() {
	flag.Parse()
}

func main() {

	c := new(ProxyConfig)

	if *config != "" {
		// read yaml file
		yamlFile, err := os.ReadFile(*config)
		if err != nil {
			log.Fatal(err)
		}
		// parse yaml file
		if err := yaml.Unmarshal(yamlFile, c); err != nil {
			log.Fatal(err)
		}
	}

	// Override debug mode
	if *debug {
		c.Debug = true
	}

	// create a new server
	s, err := gldap.NewServer(gldap.WithLogger(hclog.Default()))
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(c.bindHandler)
	r.Search(c.searchHandler)
	s.Router(r)
	go s.Run(":389")

	// stop server gracefully when ctrl-c, sigint or sigterm occurs
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
	log.Printf("\nstopping directory")
	s.Stop()
}

func (c *ProxyConfig) bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(
		gldap.WithResponseCode(gldap.ResultInvalidCredentials),
	)
	defer func() {
		w.Write(resp)
	}()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("not a simple bind message: %s", err)
		return
	}

	if c.Debug {
		log.Println("Bind request:")
		log.Printf("  ConnID %v: curBindDN: %v", r.ConnectionID(), m.UserName)
	}

	if m.UserName == c.Proxy.BindDN && m.Password == gldap.Password(c.Proxy.Password) {
		resp.SetResultCode(gldap.ResultSuccess)
		if c.Debug {
			log.Printf("  bind success to main ldap auth %v\n", m.UserName)
		}
		return
	}

	for _, ep := range c.Endpoints {
		epName := ep.Name
		if c.Debug {
			log.Printf("  trying to bind to endpoint %s", epName)
		}

		l, err := ldap.DialURL(ep.Uri)
		if err != nil {
			if c.Debug {
				log.Printf("  unable to connect to endpoint %s: %s, giving up endpoint", epName, err)
			}
			continue
		}

		defer l.Close()

		err = l.Bind(m.UserName, string(m.Password))
		if err != nil {
			resp.SetResultCode(gldap.ResultInvalidCredentials)
			if c.Debug {
				log.Printf("  bind failed to endpoint %s: %s, giving up endpoint", epName, err)
			}
			continue
		}

		resp.SetResultCode(gldap.ResultSuccess)
		if c.Debug {
			log.Printf("  bind success %v with endpoint %s\n", m.UserName, epName)
		}
		return
	}

	resp.SetResultCode(gldap.ResultInvalidCredentials)

}

func (c *ProxyConfig) searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() {
		w.Write(resp)
	}()
	m, err := r.GetSearchMessage()
	if err != nil {
		if c.Debug {
			log.Printf("not a search message: %s", err)
		}
		return
	}

	if c.Debug {
		log.Printf("New search started by conn %v", r.ConnectionID())

		log.Printf("  search base dn: %s", m.BaseDN)
		log.Printf("  search scope: %d", m.Scope)
		log.Printf("  search filter: %s", m.Filter)
	}

	for _, ep := range c.Endpoints {
		epName := ep.Name
		if c.Debug {
			log.Printf("Searching in %s", epName)
		}

		l, err := ldap.DialURL(ep.Uri)
		if err != nil {
			if c.Debug {
				log.Printf("  unable to connect to endpoint %s: %s, giving up endpoint", epName, err)
			}
			continue
		}

		defer l.Close()

		err = l.Bind(ep.BindDN, ep.Password)
		if err != nil {
			log.Printf("  WARNING: bind failed to endpoint %s: %s, giving up endpoint", epName, err)
			resp.SetResultCode(gldap.ResultInvalidCredentials)
			continue
		}

		baseDN := m.BaseDN
		if ep.Override {
			if c.Debug {
				log.Printf("  overriding base dn with %s", ep.BaseDN)
			}
			baseDN = ep.BaseDN
		}

		searchRequest := ldap.NewSearchRequest(
			baseDN,
			int(m.Scope),
			ldap.NeverDerefAliases,
			0, 0, false,
			m.Filter,
			[]string{"*"},
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err != nil {
			if c.Debug {
				log.Printf("  search failed to endpoint %s: %s, giving up endpoint", epName, err)
			}
			continue
		}

		if len(sr.Entries) > 0 {
			for _, e := range sr.Entries {

				response := make(map[string][]string)
				for _, attr := range e.Attributes {
					response[attr.Name] = attr.Values
				}

				entry := r.NewSearchResponseEntry(
					e.DN,
					gldap.WithAttributes(response),
				)
				w.Write(entry)
			}
			if c.Debug {
				log.Printf("  search success in %s", epName)
			}
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}

		if c.Debug {
			log.Printf("  no entries found in %s, giving up endpoint", epName)
		}
	}

	if c.Debug {
		log.Printf("search failed in all endpoints")
	}
	resp.SetResultCode(gldap.ResultNoSuchObject)
}
