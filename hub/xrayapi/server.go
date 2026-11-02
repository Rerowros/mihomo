package xrayapi

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

const (
	handlerService = "/xray.app.proxyman.command.HandlerService"
	statsService   = "/xray.app.stats.command.StatsService"
	v2rayHandler   = "/v2ray.core.app.proxyman.command.HandlerService"
	v2rayStats     = "/v2ray.core.app.stats.command.StatsService"

	maxMessage = 4 << 20
)

// Server is an Xray-compatible gRPC API endpoint. gRPC is HTTP/2 with a
// five-byte length prefix per message and the status in trailers, so it runs on
// the HTTP/2 server mihomo already has, without the grpc-go dependency.
type Server struct {
	listen     string
	httpServer *http.Server
	listener   net.Listener
	started    time.Time
}

var (
	serverMu sync.Mutex
	current  *Server
)

// Apply starts the API on listen (host:port), or stops it when listen is empty.
// Re-applying the same address keeps the running server.
func Apply(listen string) {
	serverMu.Lock()
	defer serverMu.Unlock()
	if current != nil && current.listen == listen {
		return
	}
	if current != nil {
		current.close()
		current = nil
	}
	if listen == "" {
		return
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		log.Errorln("Xray API listen %s: %s", listen, err)
		return
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &Server{
		listen:   listen,
		listener: listener,
		started:  time.Now(),
		httpServer: &http.Server{
			Protocols: &protocols,
		},
	}
	server.httpServer.Handler = http.HandlerFunc(server.handle)
	current = server
	log.Infoln("Xray API listening at: %s", listener.Addr())
	go func() {
		if err := server.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorln("Xray API serve error: %s", err)
		}
	}()
}

func (s *Server) close() {
	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	if r.Method != http.MethodPost || !strings.HasPrefix(contentType, "application/grpc") {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if encoding := r.Header.Get("Grpc-Encoding"); encoding != "" && encoding != "identity" {
		writeGRPC(w, contentType, nil, 12, "compressed requests are not supported")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxMessage+5))
	if err != nil {
		writeGRPC(w, contentType, nil, 13, err.Error())
		return
	}
	message, err := readFrame(body)
	if err != nil {
		writeGRPC(w, contentType, nil, 13, err.Error())
		return
	}
	response, status, statusMessage := dispatch(r.URL.Path, message)
	writeGRPC(w, contentType, response, status, statusMessage)
}

func writeGRPC(w http.ResponseWriter, contentType string, response []byte, status int, statusMessage string) {
	if contentType == "" {
		contentType = "application/grpc"
	}
	header := w.Header()
	header.Set("Content-Type", contentType)
	header.Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	if status == 0 {
		_, _ = w.Write(frame(response))
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	header.Set("Grpc-Status", strconv.Itoa(status))
	if statusMessage != "" {
		header.Set("Grpc-Message", url.PathEscape(statusMessage))
	}
}

func readFrame(body []byte) ([]byte, error) {
	if len(body) < 5 {
		return nil, errors.New("short gRPC frame")
	}
	if body[0] != 0 {
		return nil, errors.New("compressed gRPC frame")
	}
	length := int(binary.BigEndian.Uint32(body[1:5]))
	if length < 0 || length > len(body)-5 {
		return nil, errors.New("short gRPC message")
	}
	return body[5 : 5+length], nil
}

func frame(message []byte) []byte {
	out := make([]byte, 5+len(message))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(message)))
	copy(out[5:], message)
	return out
}

func dispatch(path string, message []byte) ([]byte, int, string) {
	service, method, ok := strings.Cut(path, "/")
	_ = service
	if !ok || method == "" {
		return nil, 12, "unknown method " + path
	}
	switch path {
	case handlerService + "/AlterInbound", v2rayHandler + "/AlterInbound":
		return alterInbound(message)
	case handlerService + "/GetInboundUsers", v2rayHandler + "/GetInboundUsers":
		return getInboundUsers(message)
	case handlerService + "/GetInboundUsersCount", v2rayHandler + "/GetInboundUsersCount":
		return getInboundUsersCount(message)
	case handlerService + "/ListInbounds", v2rayHandler + "/ListInbounds":
		return listInbounds(message)
	case handlerService + "/AddInbound", v2rayHandler + "/AddInbound",
		handlerService + "/RemoveInbound", v2rayHandler + "/RemoveInbound",
		handlerService + "/AddOutbound", v2rayHandler + "/AddOutbound",
		handlerService + "/RemoveOutbound", v2rayHandler + "/RemoveOutbound",
		handlerService + "/AlterOutbound", v2rayHandler + "/AlterOutbound",
		handlerService + "/ListOutbounds", v2rayHandler + "/ListOutbounds":
		return nil, 12, "method not supported by mihomo"
	case statsService + "/GetStats", v2rayStats + "/GetStats":
		return getStats(message)
	case statsService + "/QueryStats", v2rayStats + "/QueryStats":
		return queryStats(message)
	case statsService + "/GetSysStats", v2rayStats + "/GetSysStats":
		return getSysStats(message)
	case statsService + "/GetStatsOnline", v2rayStats + "/GetStatsOnline":
		return getStatsOnline(message)
	case statsService + "/GetStatsOnlineIpList", v2rayStats + "/GetStatsOnlineIpList":
		return getStatsOnlineIPList(message)
	case statsService + "/GetAllOnlineUsers", v2rayStats + "/GetAllOnlineUsers":
		return getAllOnlineUsers(message)
	case statsService + "/GetUsersStats", v2rayStats + "/GetUsersStats":
		return getUsersStats(message)
	}
	return nil, 12, "unknown method " + path
}
