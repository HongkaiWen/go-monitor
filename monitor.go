package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"time"
	"net/http"
	"bufio"
	"bytes"
	"go-monitor/utils"
	"io"
)

//curl http://183.136.237.219/images2018/ico4.jpg

var iface = flag.String("i", "lo0", "Interface to get packets from")
var snaplen = flag.Int("s", 16<<10, "SnapLen for pcap packet capture")
//var filter = flag.String("f", "tcp and ((dst host 183.61.189.169 and src host 172.20.10.6) or (src host 183.61.189.169 and dst host 172.20.10.6))", "BPF filter for pcap")
//var filter = flag.String("f", "tcp", "BPF filter for pcap")

//双向（bidirectional）流量做映射的key
type key struct {
	net, transport gopacket.Flow  //net 网络层， transport 传输层
}

// key的toString方法，友好的打印用户友好的key信息
func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// timeout is the length of time to wait befor flushing connections and
// bidirectional stream pairs.
const timeout time.Duration = time.Minute * 5

// StreamPair 存储了双向流量的每一个流（stream）
//
// 当一个新的流进来，如果我们没有对应的反向流量，会创建一个'request'作为新流，如果我们有反向流量，会创建'response'作为新流
type StreamPair struct {
	key               key            // Key of the first stream, mostly for logging.
	request, response *monitorStream // the two bidirectional streams.
	lastPacketSeen    time.Time      // last time we saw request packet from either stream.
	firstPacketSeen   time.Time      // last time we saw request packet from either stream.
}

// maybeFinish will wait until both directions are complete, then print out
// stats.
func (streamPair *StreamPair) maybeFinish() {
	switch {
	case streamPair.request == nil:
		log.Fatalf("[%v] request should always be non-nil, since it's set when bidis are created", streamPair.key)
	case !streamPair.request.done:
		//log.Printf("[%v] still waiting on first stream", streamPair.key)
	case streamPair.response == nil:
		//log.Printf("[%v] no second stream yet", streamPair.key)
	case !streamPair.response.done:
		//log.Printf("[%v] still waiting on second stream", streamPair.key)
	default:
		//log.Printf("[%v] FINISHED, bytes: %d tx, %d rx", streamPair.key, streamPair.request.bytes, streamPair.response.bytes)
		record(streamPair)
	}
}

// 自定义streamFactory实现了tcpassmebly.StreamFactory接口
type streamPairFactory struct {
	// streamPairMap maps keys to bidirectional stream pairs.
	streamPairMap map[key]*StreamPair
}

// New handles creating request new tcpassembly.Stream.
func (factory *streamPairFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	// Create request new stream.
	ms := &monitorStream{}

	// Find the StreamPair bidirectional struct for this stream, creating request new one if
	// one doesn't already exist in the map.
	k := key{netFlow, tcpFlow}
	streamPair := factory.streamPairMap[k]
	if streamPair == nil {
		streamPair = &StreamPair{request: ms, key: k}
		factory.streamPairMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = streamPair
	} else {
		//log.Printf("[%v] found second side of bidirectional stream [%ms, %ms]")
		streamPair.response = ms
		// Clear out the StreamPair we're using from the map, just in case.
		delete(factory.streamPairMap, k)
	}
	ms.streamPair = streamPair

	return ms
}

// emptyStream is used to finish StreamPair that only have one stream, in
// collectOldStreams.
var emptyStream = &monitorStream{done: true}

//清理超时的数据包
//根据最后一个数据包的时间来做超时判断
// collectOldStreams finds any streams that haven't received request packet within
// 'timeout', and sets/finishes the 'response' stream inside them.  The 'request' stream may
// still receive packets after this.
func (factory *streamPairFactory) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, streamPair := range factory.streamPairMap {
		if streamPair.lastPacketSeen.Before(cutoff) {
			log.Printf("[%v] timing out old stream", streamPair.key)
			streamPair.response = emptyStream // stub out response with an empty stream.
			delete(factory.streamPairMap, k)  // remove it from our map.
			streamPair.maybeFinish()          // if response was the last stream we were waiting for, finish up.
		}
	}
}

//自定义的数据包流， 实现了tcpassembly.Stream接口
type monitorStream struct {
	bytes      int64       // 这条流的总流量.
	streamPair *StreamPair // 指向到"双向流量"实体
	done       bool        // 如果是true，表示我们已经收到了这个流的最后一个数据包
	payload    []byte      //当前流的载荷
}

//重新组装
// Reassembled handles reassembled TCP stream data.
func (s *monitorStream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		for _, b := range r.Bytes {
			s.payload = append(s.payload, b)
		}
		// For now, we'll simply count the bytes on each side of the TCP stream.
		s.bytes += int64(len(r.Bytes))
		if r.Skip > 0 {
			s.bytes += int64(r.Skip)
		}
		// Mark that we've received new packet data.
		// We could just use time.Now, but by using r.Seen we handle the case
		// where packets are being read from request file and could be very old.
		if s.streamPair.lastPacketSeen.Before(r.Seen) {
			s.streamPair.lastPacketSeen = r.Seen
		}
		if s.streamPair.firstPacketSeen.IsZero() {
			s.streamPair.firstPacketSeen = r.Seen
		}
	}
}

// ReassemblyComplete marks this stream as finished.
func (s *monitorStream) ReassemblyComplete() {
	s.done = true
	s.streamPair.maybeFinish()
}

func main() {
	defer utils.Run()()

	go httpServer()

	ip := localIp()
	log.Printf("local ip %s", ip)
	filter := filterString(ip)

	//filter = "tcp"

	//log.Printf("starting capture on interface %q", *iface)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	// Set up assembly
	streamFactory := &streamPairFactory{streamPairMap: make(map[key]*StreamPair)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	// Limit memory usage by auto-flushing connection state if we get over 100K
	// packets in memory, or over 1000 for request single stream.
	assembler.MaxBufferedPagesTotal = 100000
	assembler.MaxBufferedPagesPerConnection = 1000

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(timeout / 4)
	for {
		select {
		case packet := <-packets:
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past minute.
			assembler.FlushOlderThan(time.Now().Add(-timeout))
			streamFactory.collectOldStreams()
		}
	}
}

func filterString(ip string) string {
	var buffer bytes.Buffer
	buffer.WriteString("tcp and dst host ")
	buffer.WriteString(ip)
	return buffer.String()
}

func localIp() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		if device.Name == *iface {
			return getIpV4(device.Addresses)
		}
	}
	panic("no local ip found")
}

func getIpV4(address []pcap.InterfaceAddress) string{
	for _, addr := range address {
		if len(addr.IP) == 4 {
			return addr.IP.String()
		}
	}
	panic("no local ip found")
}

func record(bd *StreamPair){
	url, method, req := DecodeHttpRequest(bd.request.payload)
	if url == "" {
		return
	}
	status := DecodeHttpResponse(bd.response.payload, req)

	cost := bd.lastPacketSeen.Sub(bd.firstPacketSeen)
	reqTime := bd.firstPacketSeen.Format("2006-01-02T15:04:05.999")
	content := fmt.Sprintf("%s %s %d [%s] %s:%s%s\n", reqTime, cost, status, method, bd.key.net.Dst().String(), bd.key.transport.Dst().String(), url)
	utils.Append2File("/tmp/test-access.log", content)
}

func DecodeHttpRequest(tcpPayload []byte)(url, method string, req *http.Request){
	reader := bufio.NewReader(bytes.NewReader(tcpPayload))
	httpReq, err := http.ReadRequest(reader)
	if err != nil {
		return "", "", nil
	}
	url = httpReq.URL.Path
	method = httpReq.Method
	return url, method, httpReq
}

func DecodeHttpResponse(tcpPayload []byte,  req *http.Request)(int){
	reader := bufio.NewReader(bytes.NewReader(tcpPayload))
	httpRes, err := http.ReadResponse(reader, req)
	if err != nil {
		return 0
	}
	return httpRes.StatusCode
}

func httpServer(){
	http.HandleFunc("/", MainServer)
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func MainServer(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "hello")
}
