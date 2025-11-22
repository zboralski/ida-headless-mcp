package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	websocketReadBufferSizeInBytes                       = 4096
	websocketWriteBufferSizeInBytes                      = 4096
	websocketMaximumMessageSizeInBytes                   = 1048576
	websocketPingIntervalBetweenMessagesInSeconds        = 30
	websocketPongWaitTimeoutDurationInSeconds            = 60
	websocketWriteTimeoutForIndividualMessagesInSeconds  = 10
	websocketGracefulShutdownTimeoutInSeconds            = 5
	websocketClientDisconnectionCheckIntervalInSeconds   = 1
)

type WebSocketConnectionManager struct {
	upgraderForHttpConnectionsToWebSocket               websocket.Upgrader
	modelContextProtocolServerInstance                  *mcp.Server
	loggerForWebSocketConnectionEvents                  ServerLogger
	enableVerboseDebugLoggingForAllWebSocketOperations  bool
	activeWebSocketConnectionsMutexForThreadSafety      sync.RWMutex
	activeWebSocketConnectionsMapByConnectionIdentifier map[string]*WebSocketClientConnection
	nextConnectionIdentifierForIncrementalAssignment    int64
	nextConnectionIdentifierMutexForThreadSafety        sync.Mutex
}

type WebSocketClientConnection struct {
	uniqueConnectionIdentifierForThisClient                        string
	underlyingWebSocketConnectionToRemoteClient                    *websocket.Conn
	messageChannelForOutgoingMessagesToClient                      chan []byte
	contextForCancellationOfAllConnectionOperations                context.Context
	cancellationFunctionToStopAllConnectionOperations              context.CancelFunc
	mutexForThreadSafeWriteOperationsToWebSocket                   sync.Mutex
	hasConnectionBeenClosedAndCleanedUp                            bool
	mutexForThreadSafeConnectionClosureOperations                  sync.Mutex
	timestampOfLastSuccessfulMessageReceiptFromClient              time.Time
	timestampOfMostRecentActivityOnThisConnection                  time.Time
	totalNumberOfMessagesReceivedFromClientDuringLifetime          int64
	totalNumberOfMessagesSuccessfullySentToClientDuringLifetime    int64
	totalNumberOfErrorsEncounteredDuringConnectionLifetime         int64
}

type WebSocketMessageEnvelopeForModelContextProtocol struct {
	MessageTypeIdentifierString                         string          `json:"type"`
	MessageIdentifierForRequestResponseCorrelation      string          `json:"id,omitempty"`
	ModelContextProtocolRequestPayload                  json.RawMessage `json:"request,omitempty"`
	ModelContextProtocolResponsePayload                 json.RawMessage `json:"response,omitempty"`
	ModelContextProtocolErrorPayload                    json.RawMessage `json:"error,omitempty"`
	ModelContextProtocolNotificationPayload             json.RawMessage `json:"notification,omitempty"`
}

type ServerLogger interface {
	Printf(formatString string, arguments ...interface{})
}

func CreateNewWebSocketConnectionManagerWithConfiguration(
	modelContextProtocolServerInstanceToHandleRequests *mcp.Server,
	loggerForRecordingWebSocketEvents ServerLogger,
	shouldEnableVerboseDebugLogging bool,
) *WebSocketConnectionManager {
	webSocketUpgraderWithConfiguredBufferSizes := websocket.Upgrader{
		ReadBufferSize:  websocketReadBufferSizeInBytes,
		WriteBufferSize: websocketWriteBufferSizeInBytes,
		CheckOrigin: func(httpRequestFromClient *http.Request) bool {
			shouldAllowConnectionFromAnyOrigin := true
			return shouldAllowConnectionFromAnyOrigin
		},
	}

	activeConnectionsMapInitializedAsEmpty := make(map[string]*WebSocketClientConnection)

	webSocketConnectionManager := &WebSocketConnectionManager{
		upgraderForHttpConnectionsToWebSocket:               webSocketUpgraderWithConfiguredBufferSizes,
		modelContextProtocolServerInstance:                  modelContextProtocolServerInstanceToHandleRequests,
		loggerForWebSocketConnectionEvents:                  loggerForRecordingWebSocketEvents,
		enableVerboseDebugLoggingForAllWebSocketOperations:  shouldEnableVerboseDebugLogging,
		activeWebSocketConnectionsMapByConnectionIdentifier: activeConnectionsMapInitializedAsEmpty,
		nextConnectionIdentifierForIncrementalAssignment:    1,
	}

	return webSocketConnectionManager
}

func (webSocketConnectionManager *WebSocketConnectionManager) HandleIncomingHttpConnectionUpgradeToWebSocket(
	httpResponseWriterForSendingUpgradeResponse http.ResponseWriter,
	httpRequestFromClientRequestingWebSocketUpgrade *http.Request,
) {
	remoteClientAddressAsString := httpRequestFromClientRequestingWebSocketUpgrade.RemoteAddr

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Received WebSocket upgrade request from remote client address: %s",
			remoteClientAddressAsString,
		)
	}

	upgradedWebSocketConnection, errorFromWebSocketUpgradeAttempt := webSocketConnectionManager.upgraderForHttpConnectionsToWebSocket.Upgrade(
		httpResponseWriterForSendingUpgradeResponse,
		httpRequestFromClientRequestingWebSocketUpgrade,
		nil,
	)

	if errorFromWebSocketUpgradeAttempt != nil {
		errorMessageDescribingUpgradeFailure := fmt.Sprintf(
			"Failed to upgrade HTTP connection to WebSocket protocol: %v",
			errorFromWebSocketUpgradeAttempt,
		)
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] %s",
			errorMessageDescribingUpgradeFailure,
		)
		return
	}

	connectionIdentifier := webSocketConnectionManager.generateUniqueConnectionIdentifierForNewClient()

	currentTimestampForConnectionEstablishment := time.Now()

	contextForConnectionLifecycle, cancellationFunctionForConnectionLifecycle := context.WithCancel(context.Background())

	outgoingMessageChannelWithBufferSize := make(chan []byte, 256)

	clientConnectionStructure := &WebSocketClientConnection{
		uniqueConnectionIdentifierForThisClient:                     connectionIdentifier,
		underlyingWebSocketConnectionToRemoteClient:                 upgradedWebSocketConnection,
		messageChannelForOutgoingMessagesToClient:                   outgoingMessageChannelWithBufferSize,
		contextForCancellationOfAllConnectionOperations:             contextForConnectionLifecycle,
		cancellationFunctionToStopAllConnectionOperations:           cancellationFunctionForConnectionLifecycle,
		hasConnectionBeenClosedAndCleanedUp:                         false,
		timestampOfLastSuccessfulMessageReceiptFromClient:           currentTimestampForConnectionEstablishment,
		timestampOfMostRecentActivityOnThisConnection:               currentTimestampForConnectionEstablishment,
		totalNumberOfMessagesReceivedFromClientDuringLifetime:       0,
		totalNumberOfMessagesSuccessfullySentToClientDuringLifetime: 0,
		totalNumberOfErrorsEncounteredDuringConnectionLifetime:      0,
	}

	webSocketConnectionManager.registerNewClientConnectionInActiveConnectionsMap(clientConnectionStructure)

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Successfully established WebSocket connection with identifier: %s from address: %s",
			connectionIdentifier,
			remoteClientAddressAsString,
		)
	}

	goroutineWaitGroup := &sync.WaitGroup{}
	goroutineWaitGroup.Add(2)

	go clientConnectionStructure.continuouslyReadIncomingMessagesFromClientUntilConnectionCloses(
		webSocketConnectionManager,
		goroutineWaitGroup,
	)

	go clientConnectionStructure.continuouslyWriteOutgoingMessagesToClientUntilConnectionCloses(
		webSocketConnectionManager,
		goroutineWaitGroup,
	)

	go func() {
		goroutineWaitGroup.Wait()
		webSocketConnectionManager.unregisterAndCleanUpClientConnection(connectionIdentifier)
	}()
}

func (webSocketConnectionManager *WebSocketConnectionManager) generateUniqueConnectionIdentifierForNewClient() string {
	webSocketConnectionManager.nextConnectionIdentifierMutexForThreadSafety.Lock()
	
	currentConnectionIdentifierNumber := webSocketConnectionManager.nextConnectionIdentifierForIncrementalAssignment
	webSocketConnectionManager.nextConnectionIdentifierForIncrementalAssignment = currentConnectionIdentifierNumber + 1
	
	webSocketConnectionManager.nextConnectionIdentifierMutexForThreadSafety.Unlock()

	connectionIdentifierAsString := fmt.Sprintf("ws-connection-%d", currentConnectionIdentifierNumber)
	return connectionIdentifierAsString
}

func (webSocketConnectionManager *WebSocketConnectionManager) registerNewClientConnectionInActiveConnectionsMap(
	clientConnectionToRegister *WebSocketClientConnection,
) {
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.Lock()
	
	connectionIdentifierKey := clientConnectionToRegister.uniqueConnectionIdentifierForThisClient
	webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier[connectionIdentifierKey] = clientConnectionToRegister
	
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.Unlock()

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		totalActiveConnectionsCount := len(webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier)
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Registered new connection %s, total active connections: %d",
			connectionIdentifierKey,
			totalActiveConnectionsCount,
		)
	}
}

func (webSocketConnectionManager *WebSocketConnectionManager) unregisterAndCleanUpClientConnection(
	connectionIdentifierToRemove string,
) {
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.Lock()
	
	connectionToRemove, connectionExistsInMap := webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier[connectionIdentifierToRemove]
	
	if connectionExistsInMap {
		delete(webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier, connectionIdentifierToRemove)
	}
	
	totalRemainingActiveConnections := len(webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier)
	
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.Unlock()

	if connectionExistsInMap {
		connectionToRemove.performGracefulConnectionClosureAndCleanup()
	}

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Unregistered connection %s, remaining active connections: %d",
			connectionIdentifierToRemove,
			totalRemainingActiveConnections,
		)
	}
}

func (clientConnection *WebSocketClientConnection) continuouslyReadIncomingMessagesFromClientUntilConnectionCloses(
	webSocketConnectionManager *WebSocketConnectionManager,
	waitGroupToSignalWhenReadLoopExits *sync.WaitGroup,
) {
	defer waitGroupToSignalWhenReadLoopExits.Done()

	maximumMessageSizeInBytes := int64(websocketMaximumMessageSizeInBytes)
	clientConnection.underlyingWebSocketConnectionToRemoteClient.SetReadLimit(maximumMessageSizeInBytes)

	pongWaitDurationForTimeout := time.Duration(websocketPongWaitTimeoutDurationInSeconds) * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	initialReadDeadlineTime := currentTimeForDeadlineCalculation.Add(pongWaitDurationForTimeout)
	clientConnection.underlyingWebSocketConnectionToRemoteClient.SetReadDeadline(initialReadDeadlineTime)

	clientConnection.underlyingWebSocketConnectionToRemoteClient.SetPongHandler(func(pongMessageData string) error {
		currentTimestampWhenPongReceived := time.Now()
		updatedReadDeadlineAfterPong := currentTimestampWhenPongReceived.Add(pongWaitDurationForTimeout)
		errorFromSettingReadDeadline := clientConnection.underlyingWebSocketConnectionToRemoteClient.SetReadDeadline(updatedReadDeadlineAfterPong)
		
		clientConnection.timestampOfMostRecentActivityOnThisConnection = currentTimestampWhenPongReceived
		
		return errorFromSettingReadDeadline
	})

	for {
		shouldContinueReadingMessages := true

		select {
		case <-clientConnection.contextForCancellationOfAllConnectionOperations.Done():
			shouldContinueReadingMessages = false
		default:
			shouldContinueReadingMessages = true
		}

		if !shouldContinueReadingMessages {
			break
		}

		messageTypeFromWebSocket, messageDataBytesFromClient, errorFromReadingMessage := clientConnection.underlyingWebSocketConnectionToRemoteClient.ReadMessage()

		currentTimestampAfterReadAttempt := time.Now()
		clientConnection.timestampOfMostRecentActivityOnThisConnection = currentTimestampAfterReadAttempt

		if errorFromReadingMessage != nil {
			if websocket.IsUnexpectedCloseError(
				errorFromReadingMessage,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure,
				websocket.CloseNormalClosure,
			) {
				webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
					"[WEBSOCKET ERROR] Unexpected WebSocket close error for connection %s: %v",
					clientConnection.uniqueConnectionIdentifierForThisClient,
					errorFromReadingMessage,
				)
			}
			
			clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
			break
		}

		clientConnection.totalNumberOfMessagesReceivedFromClientDuringLifetime = clientConnection.totalNumberOfMessagesReceivedFromClientDuringLifetime + 1
		clientConnection.timestampOfLastSuccessfulMessageReceiptFromClient = currentTimestampAfterReadAttempt

		messageIsTextType := messageTypeFromWebSocket == websocket.TextMessage
		messageIsBinaryType := messageTypeFromWebSocket == websocket.BinaryMessage

		if !messageIsTextType && !messageIsBinaryType {
			if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
				webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
					"[WEBSOCKET] Ignoring non-text/binary message type %d from connection %s",
					messageTypeFromWebSocket,
					clientConnection.uniqueConnectionIdentifierForThisClient,
				)
			}
			continue
		}

		if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
			messageSizeInBytes := len(messageDataBytesFromClient)
			webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
				"[WEBSOCKET] Received message from connection %s, size: %d bytes, total messages: %d",
				clientConnection.uniqueConnectionIdentifierForThisClient,
				messageSizeInBytes,
				clientConnection.totalNumberOfMessagesReceivedFromClientDuringLifetime,
			)
		}

		clientConnection.processReceivedMessageAndSendResponse(
			messageDataBytesFromClient,
			webSocketConnectionManager,
		)
	}

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Read loop terminated for connection %s",
			clientConnection.uniqueConnectionIdentifierForThisClient,
		)
	}
}

func (clientConnection *WebSocketClientConnection) processReceivedMessageAndSendResponse(
	messageDataBytesFromClient []byte,
	webSocketConnectionManager *WebSocketConnectionManager,
) {
	var parsedMessageEnvelope WebSocketMessageEnvelopeForModelContextProtocol
	
	errorFromJsonParsing := json.Unmarshal(messageDataBytesFromClient, &parsedMessageEnvelope)

	if errorFromJsonParsing != nil {
		errorMessageForClient := fmt.Sprintf("Failed to parse message JSON: %v", errorFromJsonParsing)
		
		clientConnection.sendErrorResponseToClient(
			"",
			errorMessageForClient,
			webSocketConnectionManager,
		)
		
		clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
		return
	}

	messageRequestIdentifier := parsedMessageEnvelope.MessageIdentifierForRequestResponseCorrelation
	messageTypeString := parsedMessageEnvelope.MessageTypeIdentifierString

	messageIsModelContextProtocolRequest := messageTypeString == "request"

	if !messageIsModelContextProtocolRequest {
		if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
			webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
				"[WEBSOCKET] Ignoring non-request message type '%s' from connection %s",
				messageTypeString,
				clientConnection.uniqueConnectionIdentifierForThisClient,
			)
		}
		return
	}

	requestPayloadAsRawJson := parsedMessageEnvelope.ModelContextProtocolRequestPayload

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Processing MCP request %s from connection %s",
			messageRequestIdentifier,
			clientConnection.uniqueConnectionIdentifierForThisClient,
		)
	}

	modelContextProtocolServerInstance := webSocketConnectionManager.modelContextProtocolServerInstance

	contextForProcessingThisRequest := context.Background()

	responseFromModelContextProtocolServer, errorFromProcessingRequest := modelContextProtocolServerInstance.HandleMessage(
		contextForProcessingThisRequest,
		requestPayloadAsRawJson,
	)

	if errorFromProcessingRequest != nil {
		errorMessageDescription := fmt.Sprintf("MCP request processing error: %v", errorFromProcessingRequest)
		
		clientConnection.sendErrorResponseToClient(
			messageRequestIdentifier,
			errorMessageDescription,
			webSocketConnectionManager,
		)
		
		clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
		return
	}

	clientConnection.sendSuccessResponseToClient(
		messageRequestIdentifier,
		responseFromModelContextProtocolServer,
		webSocketConnectionManager,
	)
}

func (clientConnection *WebSocketClientConnection) sendSuccessResponseToClient(
	requestIdentifierForCorrelation string,
	responsePayloadFromModelContextProtocol json.RawMessage,
	webSocketConnectionManager *WebSocketConnectionManager,
) {
	responseEnvelope := WebSocketMessageEnvelopeForModelContextProtocol{
		MessageTypeIdentifierString:                    "response",
		MessageIdentifierForRequestResponseCorrelation: requestIdentifierForCorrelation,
		ModelContextProtocolResponsePayload:            responsePayloadFromModelContextProtocol,
	}

	responseEnvelopeAsJsonBytes, errorFromJsonMarshaling := json.Marshal(responseEnvelope)

	if errorFromJsonMarshaling != nil {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] Failed to marshal response for connection %s: %v",
			clientConnection.uniqueConnectionIdentifierForThisClient,
			errorFromJsonMarshaling,
		)
		
		clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
		return
	}

	clientConnection.enqueueMessageForTransmissionToClient(
		responseEnvelopeAsJsonBytes,
		webSocketConnectionManager,
	)
}

func (clientConnection *WebSocketClientConnection) sendErrorResponseToClient(
	requestIdentifierForCorrelation string,
	errorMessageDescription string,
	webSocketConnectionManager *WebSocketConnectionManager,
) {
	errorPayloadStructure := map[string]interface{}{
		"message": errorMessageDescription,
	}

	errorPayloadAsJsonBytes, errorFromJsonMarshaling := json.Marshal(errorPayloadStructure)

	if errorFromJsonMarshaling != nil {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] Failed to marshal error payload for connection %s: %v",
			clientConnection.uniqueConnectionIdentifierForThisClient,
			errorFromJsonMarshaling,
		)
		return
	}

	errorEnvelope := WebSocketMessageEnvelopeForModelContextProtocol{
		MessageTypeIdentifierString:                    "error",
		MessageIdentifierForRequestResponseCorrelation: requestIdentifierForCorrelation,
		ModelContextProtocolErrorPayload:               errorPayloadAsJsonBytes,
	}

	errorEnvelopeAsJsonBytes, errorFromEnvelopeMarshaling := json.Marshal(errorEnvelope)

	if errorFromEnvelopeMarshaling != nil {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] Failed to marshal error envelope for connection %s: %v",
			clientConnection.uniqueConnectionIdentifierForThisClient,
			errorFromEnvelopeMarshaling,
		)
		return
	}

	clientConnection.enqueueMessageForTransmissionToClient(
		errorEnvelopeAsJsonBytes,
		webSocketConnectionManager,
	)
}

func (clientConnection *WebSocketClientConnection) enqueueMessageForTransmissionToClient(
	messageDataBytesToSend []byte,
	webSocketConnectionManager *WebSocketConnectionManager,
) {
	shouldAttemptToEnqueueMessage := true

	select {
	case <-clientConnection.contextForCancellationOfAllConnectionOperations.Done():
		shouldAttemptToEnqueueMessage = false
	default:
		shouldAttemptToEnqueueMessage = true
	}

	if !shouldAttemptToEnqueueMessage {
		if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
			webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
				"[WEBSOCKET] Cannot enqueue message for closed connection %s",
				clientConnection.uniqueConnectionIdentifierForThisClient,
			)
		}
		return
	}

	messageSizeInBytes := len(messageDataBytesToSend)

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Enqueueing message of size %d bytes for connection %s",
			messageSizeInBytes,
			clientConnection.uniqueConnectionIdentifierForThisClient,
		)
	}

	select {
	case clientConnection.messageChannelForOutgoingMessagesToClient <- messageDataBytesToSend:
		if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
			webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
				"[WEBSOCKET] Successfully enqueued message for connection %s",
				clientConnection.uniqueConnectionIdentifierForThisClient,
			)
		}
	case <-time.After(5 * time.Second):
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] Message queue full for connection %s, dropping message",
			clientConnection.uniqueConnectionIdentifierForThisClient,
		)
		clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
	}
}

func (clientConnection *WebSocketClientConnection) continuouslyWriteOutgoingMessagesToClientUntilConnectionCloses(
	webSocketConnectionManager *WebSocketConnectionManager,
	waitGroupToSignalWhenWriteLoopExits *sync.WaitGroup,
) {
	defer waitGroupToSignalWhenWriteLoopExits.Done()

	pingIntervalDuration := time.Duration(websocketPingIntervalBetweenMessagesInSeconds) * time.Second
	tickerForSendingPeriodicPingMessages := time.NewTicker(pingIntervalDuration)
	defer tickerForSendingPeriodicPingMessages.Stop()

	for {
		shouldContinueWriteLoop := true

		select {
		case <-clientConnection.contextForCancellationOfAllConnectionOperations.Done():
			shouldContinueWriteLoop = false

		case messageDataToWriteToClient := <-clientConnection.messageChannelForOutgoingMessagesToClient:
			clientConnection.writeMessageDataToWebSocketConnection(
				messageDataToWriteToClient,
				webSocketConnectionManager,
			)

		case <-tickerForSendingPeriodicPingMessages.C:
			clientConnection.sendPingMessageToClientForKeepalive(webSocketConnectionManager)
		}

		if !shouldContinueWriteLoop {
			break
		}
	}

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Write loop terminated for connection %s",
			clientConnection.uniqueConnectionIdentifierForThisClient,
		)
	}
}

func (clientConnection *WebSocketClientConnection) writeMessageDataToWebSocketConnection(
	messageDataBytesToWrite []byte,
	webSocketConnectionManager *WebSocketConnectionManager,
) {
	clientConnection.mutexForThreadSafeWriteOperationsToWebSocket.Lock()
	defer clientConnection.mutexForThreadSafeWriteOperationsToWebSocket.Unlock()

	writeTimeoutDuration := time.Duration(websocketWriteTimeoutForIndividualMessagesInSeconds) * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	writeDeadlineTime := currentTimeForDeadlineCalculation.Add(writeTimeoutDuration)
	
	clientConnection.underlyingWebSocketConnectionToRemoteClient.SetWriteDeadline(writeDeadlineTime)

	errorFromWritingMessage := clientConnection.underlyingWebSocketConnectionToRemoteClient.WriteMessage(
		websocket.TextMessage,
		messageDataBytesToWrite,
	)

	currentTimestampAfterWriteAttempt := time.Now()
	clientConnection.timestampOfMostRecentActivityOnThisConnection = currentTimestampAfterWriteAttempt

	if errorFromWritingMessage != nil {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] Failed to write message to connection %s: %v",
			clientConnection.uniqueConnectionIdentifierForThisClient,
			errorFromWritingMessage,
		)
		
		clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
		clientConnection.cancellationFunctionToStopAllConnectionOperations()
		return
	}

	clientConnection.totalNumberOfMessagesSuccessfullySentToClientDuringLifetime = clientConnection.totalNumberOfMessagesSuccessfullySentToClientDuringLifetime + 1

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		messageSizeInBytes := len(messageDataBytesToWrite)
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Successfully wrote message of size %d bytes to connection %s, total sent: %d",
			messageSizeInBytes,
			clientConnection.uniqueConnectionIdentifierForThisClient,
			clientConnection.totalNumberOfMessagesSuccessfullySentToClientDuringLifetime,
		)
	}
}

func (clientConnection *WebSocketClientConnection) sendPingMessageToClientForKeepalive(
	webSocketConnectionManager *WebSocketConnectionManager,
) {
	clientConnection.mutexForThreadSafeWriteOperationsToWebSocket.Lock()
	defer clientConnection.mutexForThreadSafeWriteOperationsToWebSocket.Unlock()

	writeTimeoutDuration := time.Duration(websocketWriteTimeoutForIndividualMessagesInSeconds) * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	writeDeadlineTime := currentTimeForDeadlineCalculation.Add(writeTimeoutDuration)
	
	clientConnection.underlyingWebSocketConnectionToRemoteClient.SetWriteDeadline(writeDeadlineTime)

	emptyPingMessageData := []byte{}
	
	errorFromWritingPing := clientConnection.underlyingWebSocketConnectionToRemoteClient.WriteMessage(
		websocket.PingMessage,
		emptyPingMessageData,
	)

	currentTimestampAfterPingAttempt := time.Now()
	clientConnection.timestampOfMostRecentActivityOnThisConnection = currentTimestampAfterPingAttempt

	if errorFromWritingPing != nil {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET ERROR] Failed to send ping to connection %s: %v",
			clientConnection.uniqueConnectionIdentifierForThisClient,
			errorFromWritingPing,
		)
		
		clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime = clientConnection.totalNumberOfErrorsEncounteredDuringConnectionLifetime + 1
		clientConnection.cancellationFunctionToStopAllConnectionOperations()
		return
	}

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Sent ping to connection %s",
			clientConnection.uniqueConnectionIdentifierForThisClient,
		)
	}
}

func (clientConnection *WebSocketClientConnection) performGracefulConnectionClosureAndCleanup() {
	clientConnection.mutexForThreadSafeConnectionClosureOperations.Lock()
	defer clientConnection.mutexForThreadSafeConnectionClosureOperations.Unlock()

	connectionAlreadyClosed := clientConnection.hasConnectionBeenClosedAndCleanedUp

	if connectionAlreadyClosed {
		return
	}

	clientConnection.cancellationFunctionToStopAllConnectionOperations()

	gracefulCloseTimeoutDuration := time.Duration(websocketGracefulShutdownTimeoutInSeconds) * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	closeMessageDeadline := currentTimeForDeadlineCalculation.Add(gracefulCloseTimeoutDuration)
	
	clientConnection.underlyingWebSocketConnectionToRemoteClient.SetWriteDeadline(closeMessageDeadline)

	closeMessagePayload := websocket.FormatCloseMessage(
		websocket.CloseNormalClosure,
		"Server closing connection",
	)
	
	errorFromSendingCloseMessage := clientConnection.underlyingWebSocketConnectionToRemoteClient.WriteMessage(
		websocket.CloseMessage,
		closeMessagePayload,
	)

	if errorFromSendingCloseMessage != nil {
	}

	clientConnection.underlyingWebSocketConnectionToRemoteClient.Close()

	close(clientConnection.messageChannelForOutgoingMessagesToClient)

	clientConnection.hasConnectionBeenClosedAndCleanedUp = true
}

func (webSocketConnectionManager *WebSocketConnectionManager) GetTotalNumberOfActiveConnections() int {
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.RLock()
	
	numberOfActiveConnections := len(webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier)
	
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.RUnlock()

	return numberOfActiveConnections
}

func (webSocketConnectionManager *WebSocketConnectionManager) CloseAllActiveConnectionsGracefully() {
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.RLock()
	
	snapshotOfActiveConnectionIdentifiers := make([]string, 0, len(webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier))
	
	for connectionIdentifier := range webSocketConnectionManager.activeWebSocketConnectionsMapByConnectionIdentifier {
		snapshotOfActiveConnectionIdentifiers = append(snapshotOfActiveConnectionIdentifiers, connectionIdentifier)
	}
	
	webSocketConnectionManager.activeWebSocketConnectionsMutexForThreadSafety.RUnlock()

	for _, connectionIdentifierToClose := range snapshotOfActiveConnectionIdentifiers {
		webSocketConnectionManager.unregisterAndCleanUpClientConnection(connectionIdentifierToClose)
	}

	if webSocketConnectionManager.enableVerboseDebugLoggingForAllWebSocketOperations {
		numberOfConnectionsClosed := len(snapshotOfActiveConnectionIdentifiers)
		webSocketConnectionManager.loggerForWebSocketConnectionEvents.Printf(
			"[WEBSOCKET] Closed all %d active WebSocket connections",
			numberOfConnectionsClosed,
		)
	}
}
