package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"gopkg.in/yaml.v3"
)

var config = flag.String("config", "", "path to config file")
var debug = flag.Bool("d", false, "enable debug mode")

type ProxyConfig struct {
	debug bool
	env   map[string]string
}

func init() {
	flag.Parse()
}

func main() {

	c := new(ProxyConfig)

	if *debug {
		c.debug = true
	}

	env := map[string]string{
		"PROXY_BASEDN":       os.Getenv("PROXY_BASEDN"),
		"PROXY_BINDDN":       os.Getenv("PROXY_BINDDN"),
		"PROXY_PASSWORD":     os.Getenv("PROXY_PASSWORD"),
		"ENDPOINT1_URI":      os.Getenv("ENDPOINT1_URI"),
		"ENDPOINT1_BASEDN":   os.Getenv("ENDPOINT1_BASEDN"),
		"ENDPOINT1_BINDDN":   os.Getenv("ENDPOINT1_BINDDN"),
		"ENDPOINT1_PASSWORD": os.Getenv("ENDPOINT1_PASSWORD"),
		"ENDPOINT2_URI":      os.Getenv("ENDPOINT2_URI"),
		"ENDPOINT2_BASEDN":   os.Getenv("ENDPOINT2_BASEDN"),
		"ENDPOINT2_BINDDN":   os.Getenv("ENDPOINT2_BINDDN"),
		"ENDPOINT2_PASSWORD": os.Getenv("ENDPOINT2_PASSWORD"),
	}

	c.env = env

	if *config != "" {
		// read yaml file
		yamlFile, err := os.ReadFile(*config)
		if err != nil {
			log.Fatal(err)
		}
		// parse yaml file
		var yamlConfig map[string]string
		if err := yaml.Unmarshal(yamlFile, &yamlConfig); err != nil {
			log.Fatal(err)
		}

		// Overriding env variables with yaml file
		for k, v := range yamlConfig {
			if _, ok := c.env[k]; ok {
				c.env[k] = v
			} else {
				log.Printf("Unknown key %s in yaml file", k)
			}
		}
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
	select {
	case <-ctx.Done():
		log.Printf("\nstopping directory")
		s.Stop()
	}
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

	log.Printf("ConnID %v: curBindDN: %v", r.ConnectionID(), m.UserName)

	if m.UserName == c.env["PROXY_BINDDN"] && m.Password == gldap.Password(c.env["PROXY_PASSWORD"]) {
		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success %v\n", m.UserName)
		return
	}

	// Bind utente dipartimento
	if strings.Contains(m.UserName, "cn=") && strings.Contains(m.UserName, "ou=users,dc=priv") {
		l, err := ldap.DialURL(c.env["ENDPOINT1_URI"])
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		err = l.Bind(m.UserName, string(m.Password))
		if err != nil {
			resp.SetResultCode(gldap.ResultInvalidCredentials)
			return
		}

		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success %v\n", m.UserName)
		return
	}
}

func (c *ProxyConfig) searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() {
		w.Write(resp)
	}()
	m, err := r.GetSearchMessage()
	if err != nil {
		log.Printf("not a search message: %s", err)
		return
	}

	log.Printf("New search started by conn %v", r.ConnectionID())

	log.Printf("search base dn: %s", m.BaseDN)
	log.Printf("search scope: %d", m.Scope)
	log.Printf("search filter: %s", m.Filter)

	// Ricerca utenti nei due server LDAP
	if m.BaseDN == c.env["PROXY_BASEDN"] {

		dip := false
		infn := false

		l, err := ldap.DialURL(c.env["ENDPOINT1_URI"])
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		err = l.Bind(c.env["ENDPOINT1_BINDDN"], c.env["ENDPOINT1_PASSWORD"])
		if err != nil {
			log.Fatal(err)
		}

		// Ricerca i dati dell'utente
		searchRequest := ldap.NewSearchRequest(
			c.env["ENDPOINT1_BASEDN"],
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(&"+m.Filter+"(PerugiaGroups=booking))",
			[]string{"dn", "sn", "givenName", "PerugiaOwner", "PerugiaGroups", "subschemaSubentry"},
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err != nil {
			log.Println(err)
		}

		dip = len(sr.Entries) == 1

		if len(sr.Entries) != 1 {
			log.Println("User does not exist or too many entries returned")

			// Utente non trovato nel server ldap di dipartimento, provare a cercare nel server infn
			dip = false
			l.Unbind()
			l.Close()

			l, err = ldap.DialURL(c.env["ENDPOINT2_URI"])
			if err != nil {
				log.Println(err)
				return
			}
			defer l.Close()

			err = l.Bind(c.env["ENDPOINT2_BINDDN"], c.env["ENDPOINT2_PASSWORD"])
			if err != nil {
				log.Fatal(err)
			}

			searchRequest = ldap.NewSearchRequest(
				c.env["ENDPOINT2_BASEDN"],
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0, 0, false,
				"(&"+m.Filter+"(l=pg))",
				//m.Filter,
				[]string{"dn", "sn", "givenName", "mail", "subschemaSubentry"},
				nil,
			)

			sr, err = l.Search(searchRequest)
			if err != nil {
				log.Println(err)
			}

			infn = len(sr.Entries) == 1

			if len(sr.Entries) != 1 {
				// Non è stato trovato neanche nel server INFN
				// Rispondere query ok ma nessun risultato
				resp.SetResultCode(gldap.ResultNoSuchObject)
				return
			}
		}

		userDN := sr.Entries[0].DN
		userSN := sr.Entries[0].GetAttributeValue("sn")
		userGivenName := sr.Entries[0].GetAttributeValue("givenName")
		userEmail := sr.Entries[0].GetAttributeValue("mail")
		userSubentry := sr.Entries[0].GetAttributeValue("subschemaSubentry")

		// Ricerca email nel ramo anagrafica per dipartimento
		if dip {
			baseDN := fmt.Sprintf("cn=%s,ou=people,dc=priv", sr.Entries[0].GetAttributeValue("PerugiaOwner"))

			searchRequest = ldap.NewSearchRequest(
				baseDN,
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0, 0, false,
				"(objectClass=*)",
				[]string{"mail"},
				nil,
			)

			sr, err = l.Search(searchRequest)
			if err != nil {
				log.Println(err)
				return
			}

			if len(sr.Entries) != 1 {
				return
			}

			userEmail = sr.Entries[0].GetAttributeValue("mail")
		}

		if dip || infn {
			entry := r.NewSearchResponseEntry(
				userDN,
				gldap.WithAttributes(map[string][]string{
					"givenname":         {userGivenName},
					"sn":                {userSN},
					"mail":              {userEmail},
					"subschemaSubentry": {userSubentry},
				}),
			)
			w.Write(entry)
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}

		resp.SetResultCode(gldap.ResultNoSuchObject)
	}
}
