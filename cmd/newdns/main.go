package main

import (
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	domainsToAddresses = map[string]net.IP{
		"google.com.": net.ParseIP("1.2.3.4"),
	}
	DNSUpstream = "10.2.255.2:53"
	
	port = 8053

)

type handler struct{
	client *dns.Client
}

func (h *handler)  forward(q dns.Question, recursive bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = recursive
	result, _, err := h.client.Exchange(m, DNSUpstream)
	if err != nil {
		log.WithError(err).WithField("m", m).Warn("Upstream query failed or timed-out")
		return nil, err
	}
	return result, nil
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	recursive := msg.RecursionDesired

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			msg.Authoritative = true
			domain := q.Name
			address, ok := domainsToAddresses[domain]
			if ok {
				log.WithField("domain", q.Name).WithField("address", address).Debugf("inner ip")
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60 },
					A: address,
				})
			} else {
				result, err := h.forward(q, recursive)
				if err != nil {
					log.WithError(err).Error("forward")
				}
				if result != nil {
					msg.Answer = append(msg.Answer, result.Answer...)
				}
			}
		default:
			result, err := h.forward(q, recursive)
			if err != nil {
				log.WithError(err).Error("forward")
			}
			if result != nil {
				msg.Answer = append(msg.Answer, result.Answer...)
			}
		}
	}

	w.WriteMsg(&msg)
}

func main() {
	log.SetLevel(log.TraceLevel)
	srv := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	srv.Handler = &handler{
		client: &dns.Client{
			Net:          "udp",
			ReadTimeout:  time.Duration(3) * time.Second,
			WriteTimeout: time.Duration(3) * time.Second,
		},
	}
	log.Printf("listend @%v/%v", srv.Addr,srv.Net)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set udp listener %s\n", err.Error())
	}
}
