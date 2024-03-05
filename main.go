package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
)

/*
	DNS协议中所有通信都是消息格式进行，每条消息由五个部分组成，标题、问题、答案、权限和附加空格
	DNS标题格式：https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md
*/

// DNS 标题
type DNSHeader struct {
	ID      uint16 // 16 bit 数据包标识符 (ID)	 分配给查询数据包的随机 ID。响应数据包必须使用相同的 ID 进行回复。
	QR      uint8  // 8 bit 查询/响应指示器 (QR) 1为回复包，0为提问包。
	OPCODE  uint8  // 4 bit 操作码（OPCODE）指定消息中的查询类型。
	AA      uint8  // 1 bit 权威答案（AA）1 如果响应服务器“拥有”所查询的域，即它是权威的。
	TC      uint8  // 1 bit 截断 (TC) 如果消息大于 512 字节，则为 1。UDP 响应中始终为 0。
	RD      uint8  // 1 bit 所需递归 (RD) 如果服务器应递归解析此查询，则发送者将其设置为 1，否则设置为 0。
	RA      uint8  // 1 bit 可用递归 (RA) 服务器将此设置为 1 以指示递归可用。
	Z       uint8  // 3 bit 保留 (Z) 由 DNSSEC 查询使用。一开始，它被保留以供将来使用。
	RCODE   uint8  // 4 bit 响应代码 (RCODE) 响应代码指示响应的状态。
	QDCOUNT uint16 // 16 bit 问题数 (QDCOUNT) 问题部分中的问题数量。
	ANCOUNT uint16 // 16 bit 答复记录计数 (ANCOUNT) 答案部分的记录数。
	NSCOUNT uint16 // 16 bit 规范记录计数 (NSCOUNT) 权限部分中的记录数。
	ARCOUNT uint16 // 16 附加记录计数 (ARCOUNT) 附加部分中的记录数。
}

type DNSQuestion struct {
	QNAME  string // 域名，表示为“标签”序列（更多内容见下文）
	QTYPE  uint16 // 2字节int；记录类型（1 表示 A 记录，5 表示 CNAME 记录等，
	QCLASS uint16 // 2字节整型；通常设置为1
}

type DNSAnswer struct {
	NAME     string // 编码为标签序列的域名。
	TYPE     uint16 // 2 bit 1对于 A 记录、5CNAME 记录等，完整列表请参见此处 https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
	CLASS    uint16 // 2 bit 通常设置为1
	TTL      uint32 // 4 bit 重新查询之前记录可以缓存的持续时间（以秒为单位）。
	RDLENGTH uint16 // 2 bit RDATA 字段的长度（以字节为单位）。
	RDATA    []byte // 特定于记录类型的数据。
}

type DNSMessage struct {
	Header   DNSHeader
	Question []DNSQuestion
	Answer   []DNSAnswer
}

func (header *DNSHeader) Serialize() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer[0:2], header.ID)
	buffer[2] = header.QR<<7 | header.OPCODE<<3 | header.AA<<2 | header.TC<<1 | header.RD
	buffer[3] = header.RA<<7 | header.Z<<4 | header.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], header.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], header.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], header.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], header.ARCOUNT)
	return buffer
}

func (q *DNSQuestion) SerializeName() []byte {
	labels := strings.Split(q.QNAME, ".")
	var data []byte
	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}
	data = append(data, '\x00')
	return data
}

//goland:noinspection ALL
func (q *DNSQuestion) Serialize() []byte {
	labels := q.SerializeName()
	size := len(labels) + 4
	bytes := make([]byte, size)
	copy(bytes, labels)
	bytes[size-4] = byte(q.QTYPE >> 8)
	bytes[size-3] = byte(q.QTYPE)
	bytes[size-2] = byte(q.QCLASS >> 8)
	bytes[size-1] = byte(q.QCLASS)
	return bytes
}

func SerialiazeName(name string) ([]byte, error) {
	labels := strings.Split(name, ",")
	var data []byte
	for _, label := range labels {
		data = append(data, byte(len(labels)))
		data = append(data, label...)
	}
	data = append(data, '\x00')
	return data, nil
}

func (a *DNSAnswer) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	name, _ := SerialiazeName(a.NAME)
	buf.Write(name)

	err := binary.Write(&buf, binary.BigEndian, a.TYPE)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer TYPE: %w", err)
	}

	err = binary.Write(&buf, binary.BigEndian, a.CLASS)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer CLASS: %w", err)
	}

	err = binary.Write(&buf, binary.BigEndian, a.TTL)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer TTL: %w", err)
	}

	err = binary.Write(&buf, binary.BigEndian, a.RDLENGTH)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer RDLENGTH: %w", err)
	}

	buf.Write(a.RDATA)
	return buf.Bytes(), nil
}

func (message *DNSMessage) Serliaze() ([]byte, error) {
	var data []byte
	data = append(data, message.Header.Serialize()...)
	for _, q := range message.Question {
		data = append(data, q.Serialize()...)
	}
	for _, a := range message.Answer {
		answer, err := a.Serialize()
		if err != nil {
			return nil, fmt.Errorf("unable to write answer %w", err)
		}
		data = append(data, answer...)
	}
	return data, nil
}

func ParseDNSHeader(r *bytes.Reader) (DNSHeader, error) {
	h := DNSHeader{}
	// read ID
	err := binary.Read(r, binary.BigEndian, &h.ID)
	if err != nil {
		return DNSHeader{}, err
	}
	// read QR, OPCODE, AA, TC, RD (1 byte)
	thirdflags, err := r.ReadByte()
	if err != nil {
		return h, fmt.Errorf("error reading DNS header on 3rd byte %w", err)
	}
	h.QR = thirdflags >> 7
	h.OPCODE = (thirdflags >> 3) & 0xF
	h.AA = thirdflags & 0x4
	h.TC = thirdflags & 0x2
	h.RD = thirdflags & 0x1
	// read RA, RCODE (1 byte)
	fourFlags, err := r.ReadByte()
	if err != nil {
		return h, fmt.Errorf("error reading DNS header on 4th byte %w", err)
	}
	h.RA = fourFlags >> 7
	h.RCODE = fourFlags & 0xF

	// read QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	binary.Read(r, binary.BigEndian, &h.QDCOUNT)
	binary.Read(r, binary.BigEndian, &h.ANCOUNT)
	binary.Read(r, binary.BigEndian, &h.NSCOUNT)
	binary.Read(r, binary.BigEndian, &h.ARCOUNT)
	return h, nil
}

func ParseDNSName(r *bytes.Reader) (string, error) {
	var name []string
	for {
		var length byte
		err := binary.Read(r, binary.BigEndian, &length)
		if err != nil {
			return "", fmt.Errorf("error reading DNS question name length %w", err)
		}
		if length == 0 {
			break
		} else if length&0xC0 == 0xC0 { // 判断前两位是否11 ，如果是则说明用了压缩指针
			var secondOffset byte
			err := binary.Read(r, binary.BigEndian, &secondOffset)
			if err != nil {
				return "", fmt.Errorf("error reading DNS question name compressed label %w", err)
			}
			newOffset := int64(length&0x3F)<<8 + int64(secondOffset)
			r.Seek(newOffset, io.SeekStart)
		} else {
			labels := make([]byte, length)
			_, err = r.Read(labels)
			if err != nil {
				return "", fmt.Errorf("error reading DNS question name label %w", err)
			}
			name = append(name, string(labels))
		}
	}
	return strings.Join(name, "."), nil
}

func ParseDNSQuestion(r *bytes.Reader) (DNSQuestion, error) {
	q := DNSQuestion{}
	name, _ := ParseDNSName(r)
	q.QNAME = name
	err := binary.Read(r, binary.BigEndian, &q.QTYPE)
	if err != nil {
		return q, err
	}
	err = binary.Read(r, binary.BigEndian, &q.QCLASS)
	if err != nil {
		return q, err
	}
	return q, nil
}

func ParseDNSMessage(r *bytes.Reader) (DNSMessage, error) {
	header, err := ParseDNSHeader(r)
	if err != nil {
		fmt.Println("Error reading DNS message, returning empty message ", err)
		return DNSMessage{}, err
	}
	// parse incoming question
	//_, _ = r.Seek(12, io.SeekStart)
	var questions []DNSQuestion
	for i := 0; i < int(header.QDCOUNT); i++ {
		q, err := ParseDNSQuestion(r)
		if err != nil {
			return DNSMessage{}, err
		}
		questions = append(questions, q)
	}
	// parse incoming answer (is not empty if we parse a DNS response from a remote resolver)
	var answer []DNSAnswer
	for i := 0; i < int(header.ANCOUNT); i++ {
		var a DNSAnswer
		name, _ := ParseDNSName(r)
		a.NAME = name
		binary.Read(r, binary.BigEndian, &a.TYPE)
		binary.Read(r, binary.BigEndian, &a.CLASS)
		binary.Read(r, binary.BigEndian, &a.TTL)
		binary.Read(r, binary.BigEndian, &a.RDLENGTH)

		data := make([]byte, a.RDLENGTH)
		binary.Read(r, binary.BigEndian, &data)
		a.RDATA = data
		answer = append(answer, a)
	}
	return DNSMessage{
		Header:   header,
		Question: questions,
		Answer:   answer,
	}, nil
}

func createDummyDNSResponse(request *DNSMessage) (DNSMessage, error) {
	response := DNSMessage{}
	// process question
	var questions []DNSQuestion
	for i := 0; i < int(request.Header.QDCOUNT); i++ {
		q := DNSQuestion{
			QNAME:  request.Question[i].QNAME,
			QTYPE:  1,
			QCLASS: 1,
		}
		questions = append(questions, q)
	}
	response.Question = questions

	// process answer
	var answers []DNSAnswer
	for i := 0; i < int(request.Header.QDCOUNT); i++ {
		a := DNSAnswer{
			NAME:     request.Question[i].QNAME,
			TYPE:     1,
			CLASS:    1,
			TTL:      60,
			RDLENGTH: 4,
			RDATA:    []byte{8, 8, 8, 8},
		}
		answers = append(answers, a)
	}
	response.Answer = answers

	// process header
	if request.Header.OPCODE == 0 {
		response.Header.RCODE = 0
	} else {
		response.Header.RCODE = 4
	}
	response.Header = DNSHeader{
		ID:      request.Header.ID,
		QR:      1,
		OPCODE:  request.Header.OPCODE,
		AA:      0,
		TC:      0,
		RD:      request.Header.RD,
		RA:      0,
		Z:       0,
		RCODE:   response.Header.RCODE,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
	return response, nil
}

func ResolveQueryWithForwarder(remoteServerConn *net.UDPConn, requestMessage *DNSMessage) (DNSMessage, error) {
	msgFromResolve := *requestMessage
	msgFromResolve.Answer = make([]DNSAnswer, 0)
	msgFromResolve.Header.ANCOUNT = 0

	// get answer from remote DNS server
	for i, q := range requestMessage.Question {
		msgToResolver := requestMessage
		msgToResolver.Answer = make([]DNSAnswer, 0)
		msgToResolver.Question = make([]DNSQuestion, 0)
		msgToResolver.Question[0] = q
		msgToResolver.Header.QDCOUNT = 1
		msgToResolver.Header.ID = requestMessage.Header.ID + uint16(i)
		msgToResolver.Header.QR = 0

		msg, err := msgToResolver.Serliaze()
		if err != nil {
			fmt.Println("Error serializing DNS message to resolver: ", err)
			return DNSMessage{}, err
		}
		_, err = remoteServerConn.Write(msg)
		if err != nil {
			fmt.Println("Error sending data to remote DNS resolver: ", err)
			return DNSMessage{}, err
		}

		remoteBuf := make([]byte, 512)
		remoteSize, err := remoteServerConn.Read(remoteBuf)
		if err != nil {
			fmt.Println("Error receiving data from remote DNS resolver: ", err)
			return DNSMessage{}, err
		}
		d := bytes.NewReader(remoteBuf[:remoteSize])
		msgParsed, err := ParseDNSMessage(d)
		if err != nil {
			fmt.Println("error while parsing DNS message from remote DNS resolver ", err)
			return DNSMessage{}, err
		}
		fmt.Printf("Received %d bytes from resolver. [Q: %d ID: %d QDCOUNT: %d ANCOUNT: %d]\n",
			remoteSize,
			i,
			msgParsed.Header.ID,
			msgParsed.Header.QDCOUNT,
			msgParsed.Header.ANCOUNT,
		)
		msgFromResolve.Answer = append(msgFromResolve.Answer, msgParsed.Answer...)
	}

	// process header
	msgFromResolve.Header.QR = 1
	msgFromResolve.Header.AA = 0
	msgFromResolve.Header.TC = 0
	msgFromResolve.Header.RA = 0
	msgFromResolve.Header.QDCOUNT = uint16(len(msgFromResolve.Question))
	msgFromResolve.Header.ANCOUNT = uint16(len(msgFromResolve.Answer))
	if msgFromResolve.Header.OPCODE == 0 {
		msgFromResolve.Header.RCODE = 0
	} else {
		msgFromResolve.Header.RCODE = 4
	}
	return msgFromResolve, nil
}

func main() {
	startUDPServer()
}

/*
本地测试 使用 echo "hehei" | nc -u 127.0.0.1 8888命令向 udp服务器发消息
*/
func startUDPServer() {
	var resolver string
	var remoteServerAddr *net.UDPAddr
	var remoteServerConn *net.UDPConn
	flag.StringVar(&resolver, "resolver", "", "resolver")
	flag.Parse()

	// 设置一个UDP服务器
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8888")
	if err != nil {
		fmt.Println("Failed to resolve UDP address: ", err)
		return
	}
	resolverIsUsed := resolver != ""
	if resolverIsUsed {
		fmt.Println("Resolver is used: ", resolver)
		remoteServerAddr, err = net.ResolveUDPAddr("udp", resolver)
		if err != nil {
			fmt.Println("Failed to resolve remote server address:", err)
		}
		remoteServerConn, err = net.DialUDP("udp", nil, remoteServerAddr)
		if err != nil {
			fmt.Println("Failed to connect to remote server:", err)
		}
		defer remoteServerConn.Close()
		fmt.Println("Connected to resolver")
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)
	for {
		// read from incoming DNS packets
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		dataReader := bytes.NewReader(buf[:size])
		parsedData, err := ParseDNSMessage(dataReader)
		if err != nil {
			fmt.Println("error while parsing DNS message ", err)
			continue
		}

		// 返回一个response
		var response DNSMessage
		if resolverIsUsed {
			response, err = ResolveQueryWithForwarder(remoteServerConn, &parsedData)
			if err != nil {
				fmt.Println("Failed to get DNS message from remote server: ", err)
			}
		} else {
			response, err = createDummyDNSResponse(&parsedData)
			if err != nil {
				fmt.Println("Failed to get DNS message from remote server: ", err)
			}
		}
		serializeResponse, err := response.Serliaze()
		if err != nil {
			fmt.Println("Failed to serialize message: ", err)
		}
		_, err = udpConn.WriteToUDP(serializeResponse, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
