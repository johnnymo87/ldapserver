package main

import (
	"crypto/tls"
	"log"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
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
sPlc1sJe4lsoxQYptMjV
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5Wacc+lW+Umj/N750fXj+BpkCtFqxseGM5RS3vkGgzrXd8j0
SfvUHFijWIsdRcqP4f64vq95fIiXs2JB8qifvyUKocGq9jKnYl7JVkYY1/e+H3xI
mT5EwwYQF89TuGybFZ/GLjF/PlEErJcAZwZ5pLacJKrvSEhXyA+XSqnoO45EfiMm
nyGjpK68HC0Qi5U4iXfRD6CSwxuTcFMK35O532wk0VmeRwn9xeGsw3LtNiiL3+fH
7wP1/Pgzb9sQCKS+pPLFr8Gd+RJOanA+J3BDHbCBXW8Tw7lLQPiAK5FyBEOMcwRt
KTWOBofetA5uNOPlNjIY2c3HKt3LjcFCh8iHkwIDAQABAoIBAQDLGlZaqbU/cVun
fyNgKXx1Jah9i3wmEnFXKXNVxtVlSquKenkPJ89caX313vVD3VwWkxeufF3rTGRD
hjMtTO5ipcEMBhP/dkmMZq+LmvRUAhxqc/cy9laa9Ls62W0eU8nbE2K7c0ddPQ4O
YIMStEDu/F6yeETyklpl3qfsixH55wZ80erNhoJHcudxuHh+Xa9OCGvj7X4pbm87
6ciYymkTnB03hHIWVSfD8wSrUf4Zl836TGoqgYbPV+oUHtpRrk88yEl7C40AcxF3
YOG/X5RvvwDddUcVC+g8DEOqmY97AUnlzbkrElotC5IrmwiVD4xDkn/YdKTqZXzF
b2h47wdBAoGBAPvrZsLFpM8L7MXoHyQKiQ0s2U+4OSdv5vSb7ge65WP3rTU9vxte
EcMlNapMC68GyB9KNMNDAKQj3c3dzFU5tEvBMDuJrHO6nTPQ4X4VF+j4hqT11ZES
qzLbDmvTVaiOgdPFM84P5NU7qjmQ0LUqNhj04VTgc1LST3dXOv2NMi09AoGBAOkd
1anX7ccWYzucEkFlPhZ8UOGk8U97PvWKexZnRVKPlugmAMGMNz2EWjoHfIUdGksd
eLCjNUHj+tYKTlbrR2nXIEr0Zj03JqIN2MKuswudeLV9NXZc96jCBDMXnokGbjmw
W57iNADVbd3uoKNnrr65HVwe9XMdY8QWbBbYh3UPAoGBANIUEHHEWBfBHgY7+Bwa
HQg7qkzsl9znWHYLwof3t2uSE4Mepsuvuqg9027cU7H1udU+EJn0uggnUMRofglk
QZIa3JoJySIJMScQvbpi5LmG5uGRkDOWmeWi/3ezmO8jR+jNvtHMN0wKoX234hPx
y4MsUuxw8DrU3yfqOmtO39URAoGAAsKfrQspfZn+Qs5uSOfx/EIskv9o/A/xhubE
3lcKsxeQKd+JUsFeRhQzHUzJZKobjZgjvbOxBb61UaN9mfnfNpmdgEW0kDT++BxB
3MxEwnZy33NEFsqzBASIGDLHZcf1tikobJExHHFqg543uLeZkhiPCHA1Z8+JRuEd
Fogp0nECgYAI7LCco9JH8Z84X/3YYwc4eiOSioNvXBWUwPYJyG0gvvVNdOUgri4X
pBzy8UqQGm5wKRD2hxSewfwcmH6FmSvrAorbIDOg2+pkBrPbSIxjH8jHTRFiHBdc
tAtu4zM3Niy9+osC9SZf+eR3p9dfRd82KD7cpLXidClx9X9coYfLbw==
-----END RSA PRIVATE KEY-----
`)

// getTLSconfig returns a tls configuration used
// to build a TLSlistener for TLS or StartTLS
func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}, nil
}

func main() {
	//Create a new LDAP Server
	server := ldap.NewServer()

	//Set routes, here, we only serve bindRequest
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch)
	server.Handle(routes)

	//SSL
	secureConn := func(s *ldap.Server) {
		config, _ := getTLSconfig()
		s.Listener = tls.NewListener(s.Listener, config)
	}
	go server.ListenAndServe(":389", secureConn)

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	<-ch
	close(ch)
	server.Stop()
}

// handleBind returns Success if login == jon
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if string(r.Name()) == "jon" {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	e := ldap.NewSearchResultEntry("cn=Valere JEANTET, " + string(r.BaseObject()))
	e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
	e.AddAttribute("company", "SODADI")
	e.AddAttribute("department", "DSI/SEC")
	e.AddAttribute("l", "Ferrieres en brie")
	e.AddAttribute("mobile", "0612324567")
	e.AddAttribute("telephoneNumber", "0612324567")
	e.AddAttribute("cn", "Valère JEANTET")
	w.Write(e)

	// Add second user to make client say, "Error authenticating user: Multiple entries found for the search filter"
	// e = ldap.NewSearchResultEntry("cn=Claire Thomas, " + string(r.BaseObject()))
	// e.AddAttribute("mail", "claire.thomas@gmail.com")
	// e.AddAttribute("cn", "Claire THOMAS")
	// w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
