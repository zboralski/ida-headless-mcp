package server

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (serverInstance *Server) HTTPMux(modelContextProtocolServerForHandlingRequests *mcp.Server) http.Handler {
	serverSentEventsHandlerForLegacyClients := mcp.NewSSEHandler(func(httpRequestFromClient *http.Request) *mcp.Server {
		shouldLogDebugInformationForThisRequest := serverInstance.debug
		if shouldLogDebugInformationForThisRequest {
			remoteClientAddressAsString := httpRequestFromClient.RemoteAddr
			httpMethodFromRequest := httpRequestFromClient.Method
			urlPathFromRequest := httpRequestFromClient.URL.Path
			serverInstance.logger.Printf("[DEBUG] SSE connection from %s: %s %s", remoteClientAddressAsString, httpMethodFromRequest, urlPathFromRequest)
		}
		return modelContextProtocolServerForHandlingRequests
	}, nil)

	streamableHttpHandlerForModernClients := mcp.NewStreamableHTTPHandler(func(httpRequestFromClient *http.Request) *mcp.Server {
		return modelContextProtocolServerForHandlingRequests
	}, &mcp.StreamableHTTPOptions{
		JSONResponse:   true,
		SessionTimeout: serverInstance.sessionTimeout,
		Stateless:      true,
	})

	webSocketConnectionManagerForRealtimeBidirectionalCommunication := CreateNewWebSocketConnectionManagerWithConfiguration(
		modelContextProtocolServerForHandlingRequests,
		serverInstance.logger,
		serverInstance.debug,
	)

	serverInstance.webSocketManagerForActiveConnections = webSocketConnectionManagerForRealtimeBidirectionalCommunication

	httpRequestMultiplexerForRoutingIncomingRequests := http.NewServeMux()
	
	httpRequestMultiplexerForRoutingIncomingRequests.Handle("/sse", http.HandlerFunc(func(httpResponseWriter http.ResponseWriter, httpRequestFromClient *http.Request) {
		shouldLogDebugInformationForThisRequest := serverInstance.debug
		if shouldLogDebugInformationForThisRequest {
			httpMethodFromRequest := httpRequestFromClient.Method
			urlPathFromRequest := httpRequestFromClient.URL.Path
			remoteClientAddressAsString := httpRequestFromClient.RemoteAddr
			serverInstance.logger.Printf("[SSE] %s %s from %s", httpMethodFromRequest, urlPathFromRequest, remoteClientAddressAsString)
		}
		serverSentEventsHandlerForLegacyClients.ServeHTTP(httpResponseWriter, httpRequestFromClient)
	}))
	
	httpRequestMultiplexerForRoutingIncomingRequests.Handle("/ws", http.HandlerFunc(func(httpResponseWriter http.ResponseWriter, httpRequestFromClient *http.Request) {
		shouldLogDebugInformationForThisRequest := serverInstance.debug
		if shouldLogDebugInformationForThisRequest {
			httpMethodFromRequest := httpRequestFromClient.Method
			urlPathFromRequest := httpRequestFromClient.URL.Path
			remoteClientAddressAsString := httpRequestFromClient.RemoteAddr
			serverInstance.logger.Printf("[WEBSOCKET] %s %s from %s", httpMethodFromRequest, urlPathFromRequest, remoteClientAddressAsString)
		}
		webSocketConnectionManagerForRealtimeBidirectionalCommunication.HandleIncomingHttpConnectionUpgradeToWebSocket(httpResponseWriter, httpRequestFromClient)
	}))
	
	httpRequestMultiplexerForRoutingIncomingRequests.Handle("/", http.HandlerFunc(func(httpResponseWriter http.ResponseWriter, httpRequestFromClient *http.Request) {
		shouldLogDebugInformationForThisRequest := serverInstance.debug
		if shouldLogDebugInformationForThisRequest {
			httpMethodFromRequest := httpRequestFromClient.Method
			urlPathFromRequest := httpRequestFromClient.URL.Path
			remoteClientAddressAsString := httpRequestFromClient.RemoteAddr
			serverInstance.logger.Printf("[HTTP] %s %s from %s", httpMethodFromRequest, urlPathFromRequest, remoteClientAddressAsString)
		}
		streamableHttpHandlerForModernClients.ServeHTTP(httpResponseWriter, httpRequestFromClient)
	}))
	
	return httpRequestMultiplexerForRoutingIncomingRequests
}
