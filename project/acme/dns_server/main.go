package main

import (
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"strconv"
)

var opts struct {
	Challenge string `long:"type" description:"Sets challenge type to http-01" required:"true"`
	Directory string `long:"dir" decription:"URL of the ACME server directory" required:"true"`
	Domain    string `long:"domain" description:"Domain name of the customer server" required:"true"`
	Revoke    bool   `long:"revoke" description:"Sets the client to immedietly revoke the certificate after obtaining it"`
	Record    string `long:"record" description:"IPv4 address which must be returned for all A and AAAA-record queries" required:"true"`
}

var dnsKey string
var dnsName string
var dnsCnt int
var txtName string

var dnsTable map[string]string

type dnsHandler struct{}

func (this *dnsHandler) ServeDNS(resp dns.ResponseWriter, req *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(req)

	var ipAddr string
	// Only handles A records
	if req.Question[0].Qtype == dns.TypeAAAA {
		m.Authoritative = true
		dom := m.Question[0].Name
		ipAddr = opts.Record
		prs := true
		//ipAddr = fmt.Sprintf("::FFFF:%s", ipAddr)
		if prs {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dom, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(ipAddr),
			})
		}
		resp.WriteMsg(&m)
	} else if req.Question[0].Qtype == dns.TypeA {
		m.Authoritative = true
		dom := m.Question[0].Name
		ipAddr = opts.Record
		prs := true
		if prs {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ipAddr),
			})
		}
		resp.WriteMsg(&m)
	} else if req.Question[0].Qtype == dns.TypeTXT {

		switch dnsCnt {
		case 1:
			txtName = req.Question[0].Name
			dnsCnt++
		case 2:
			dnsKey = req.Question[0].Name
			if last := len(dnsKey) - 1; last >= 0 && dnsKey[last] == '.' {
				log.WithField("Key", dnsKey).Info("Received Key from ACME client")
				dnsKey = dnsKey[:last]
			}
			dnsTable[txtName] = dnsKey
			dnsCnt++
		default:
			// if record name doesn't exist, then we add it to the map with empty
			// value and waits for the corresponding authorization key
			if !recordInMap(req.Question[0].Name, dnsTable) {
				txtName = req.Question[0].Name
				dnsTable[txtName] = ""
				dnsCnt = 2
				break
			}

			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{dnsTable[req.Question[0].Name]},
			})
			log.WithFields(log.Fields{
				"Question": m.Question,
				"Answer":   m.Answer,
			}).Info("Writing TXT reply")
			resp.WriteMsg(&m)
		}
	}
}

func recordInMap(domName string, table map[string]string) bool {
	if table[domName] != "" {
		return true
	} else {
		return false
	}
}

func main() {

	dnsCnt = 1
	_, err := flags.ParseArgs(&opts, os.Args)

	dnsTable = make(map[string]string)
	// set up DNS server to run on udp -port 10053
	server := &dns.Server{Addr: ":" + strconv.Itoa(10053), Net: "udp"}
	server.Handler = &dnsHandler{}
	err = server.ListenAndServe()

	if err != nil {
		log.WithError(err).Error("Failed to initialize DNS server... Exiting")
		os.Exit(0)
	} else {
		log.WithField("Port", 10053).Info("Sucessfully Initialized DNS server")
	}
}
