package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zboralski/ida-headless-mcp/internal/session"
	"github.com/zboralski/ida-headless-mcp/internal/worker"
)

type MockWorkerControllerForWebSocketTesting struct{}

func (mockController *MockWorkerControllerForWebSocketTesting) Start(sessionIdentifier string) error {
	return nil
}

func (mockController *MockWorkerControllerForWebSocketTesting) Stop(sessionIdentifier string) error {
	return nil
}

func (mockController *MockWorkerControllerForWebSocketTesting) Get(sessionIdentifier string) (worker.Client, error) {
	return nil, nil
}

type MockLoggerForWebSocketTesting struct {
	loggedMessagesCollectedDuringTest []string
}

func (mockLogger *MockLoggerForWebSocketTesting) Printf(formatString string, argumentsForFormatting ...interface{}) {
}

func TestWebSocketConnectionEstablishmentAndBasicCommunication(testingContext *testing.T) {
	maximumNumberOfConcurrentSessions := 10
	sessionRegistryForTest := session.NewRegistry(maximumNumberOfConcurrentSessions)
	
	mockWorkerController := &MockWorkerControllerForWebSocketTesting{}
	mockLogger := &MockLoggerForWebSocketTesting{
		loggedMessagesCollectedDuringTest: make([]string, 0),
	}
	
	sessionTimeoutDuration := 30 * time.Minute
	debugLoggingEnabled := true
	nilSessionStore := (*session.Store)(nil)
	
	serverInstance := New(
		sessionRegistryForTest,
		mockWorkerController,
		mockLogger,
		sessionTimeoutDuration,
		debugLoggingEnabled,
		nilSessionStore,
	)

	modelContextProtocolServerInstance := mcp.NewServer(&mcp.Implementation{
		Name:    "ida-headless-test",
		Version: "0.1.0-test",
	}, nil)

	serverInstance.RegisterTools(modelContextProtocolServerInstance)

	httpHandlerForTestServer := serverInstance.HTTPMux(modelContextProtocolServerInstance)

	httpTestServer := httptest.NewServer(httpHandlerForTestServer)
	defer httpTestServer.Close()

	httpServerUrlAsString := httpTestServer.URL
	webSocketUrlForConnection := strings.Replace(httpServerUrlAsString, "http://", "ws://", 1) + "/ws"

	webSocketDialerForClientConnection := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}

	clientWebSocketConnection, httpResponseFromUpgrade, errorFromDialing := webSocketDialerForClientConnection.Dial(
		webSocketUrlForConnection,
		nil,
	)

	if errorFromDialing != nil {
		errorMessageForFailedConnection := "Failed to establish WebSocket connection: " + errorFromDialing.Error()
		testingContext.Fatal(errorMessageForFailedConnection)
	}

	defer clientWebSocketConnection.Close()

	httpStatusCodeFromUpgradeResponse := httpResponseFromUpgrade.StatusCode
	expectedStatusCodeForSuccessfulUpgrade := http.StatusSwitchingProtocols
	
	statusCodeDoesNotMatchExpected := httpStatusCodeFromUpgradeResponse != expectedStatusCodeForSuccessfulUpgrade
	
	if statusCodeDoesNotMatchExpected {
		testingContext.Errorf(
			"Expected HTTP status %d for WebSocket upgrade, got %d",
			expectedStatusCodeForSuccessfulUpgrade,
			httpStatusCodeFromUpgradeResponse,
		)
	}

	uniqueRequestIdentifierForToolsListRequest := "test-request-tools-list-12345"
	
	modelContextProtocolRequestStructure := map[string]interface{}{
		"method": "tools/list",
		"params": map[string]interface{}{},
	}

	requestPayloadAsJsonBytes, errorFromMarshalingRequest := json.Marshal(modelContextProtocolRequestStructure)
	
	if errorFromMarshalingRequest != nil {
		testingContext.Fatal("Failed to marshal request:", errorFromMarshalingRequest)
	}

	messageEnvelopeForRequest := map[string]interface{}{
		"type":    "request",
		"id":      uniqueRequestIdentifierForToolsListRequest,
		"request": json.RawMessage(requestPayloadAsJsonBytes),
	}

	envelopeAsJsonBytes, errorFromMarshalingEnvelope := json.Marshal(messageEnvelopeForRequest)
	
	if errorFromMarshalingEnvelope != nil {
		testingContext.Fatal("Failed to marshal envelope:", errorFromMarshalingEnvelope)
	}

	writeTimeoutDuration := 5 * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	writeDeadlineTime := currentTimeForDeadlineCalculation.Add(writeTimeoutDuration)
	
	clientWebSocketConnection.SetWriteDeadline(writeDeadlineTime)

	errorFromWritingMessage := clientWebSocketConnection.WriteMessage(
		websocket.TextMessage,
		envelopeAsJsonBytes,
	)

	if errorFromWritingMessage != nil {
		testingContext.Fatal("Failed to write message to WebSocket:", errorFromWritingMessage)
	}

	readTimeoutDuration := 5 * time.Second
	currentTimeForReadDeadline := time.Now()
	readDeadlineTime := currentTimeForReadDeadline.Add(readTimeoutDuration)
	
	clientWebSocketConnection.SetReadDeadline(readDeadlineTime)

	messageTypeFromServer, messageDataBytesFromServer, errorFromReadingMessage := clientWebSocketConnection.ReadMessage()

	if errorFromReadingMessage != nil {
		testingContext.Fatal("Failed to read response from WebSocket:", errorFromReadingMessage)
	}

	messageTypeIsTextMessage := messageTypeFromServer == websocket.TextMessage
	
	if !messageTypeIsTextMessage {
		testingContext.Errorf(
			"Expected text message type (%d), got %d",
			websocket.TextMessage,
			messageTypeFromServer,
		)
	}

	var responseEnvelopeParsedFromJson map[string]interface{}
	
	errorFromUnmarshalingResponse := json.Unmarshal(messageDataBytesFromServer, &responseEnvelopeParsedFromJson)

	if errorFromUnmarshalingResponse != nil {
		testingContext.Fatal("Failed to unmarshal response:", errorFromUnmarshalingResponse)
	}

	messageTypeFromEnvelope, messageTypeExists := responseEnvelopeParsedFromJson["type"].(string)
	
	if !messageTypeExists {
		testingContext.Fatal("Response envelope missing 'type' field")
	}

	messageTypeIsResponse := messageTypeFromEnvelope == "response"
	messageTypeIsError := messageTypeFromEnvelope == "error"

	if messageTypeIsError {
		errorPayloadFromEnvelope := responseEnvelopeParsedFromJson["error"]
		testingContext.Fatalf("Server returned error: %v", errorPayloadFromEnvelope)
	}

	if !messageTypeIsResponse {
		testingContext.Errorf(
			"Expected message type 'response', got '%s'",
			messageTypeFromEnvelope,
		)
	}

	messageIdentifierFromEnvelope, identifierExists := responseEnvelopeParsedFromJson["id"].(string)
	
	if !identifierExists {
		testingContext.Fatal("Response envelope missing 'id' field")
	}

	identifierMatchesRequest := messageIdentifierFromEnvelope == uniqueRequestIdentifierForToolsListRequest
	
	if !identifierMatchesRequest {
		testingContext.Errorf(
			"Response ID mismatch: expected '%s', got '%s'",
			uniqueRequestIdentifierForToolsListRequest,
			messageIdentifierFromEnvelope,
		)
	}

	testingContext.Log("WebSocket connection test completed successfully")
}

func TestWebSocketConnectionManagerActiveConnectionTracking(testingContext *testing.T) {
	mockLogger := &MockLoggerForWebSocketTesting{
		loggedMessagesCollectedDuringTest: make([]string, 0),
	}

	modelContextProtocolServerInstance := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)

	debugLoggingEnabled := false

	webSocketConnectionManager := CreateNewWebSocketConnectionManagerWithConfiguration(
		modelContextProtocolServerInstance,
		mockLogger,
		debugLoggingEnabled,
	)

	initialNumberOfActiveConnections := webSocketConnectionManager.GetTotalNumberOfActiveConnections()
	expectedInitialConnectionCount := 0

	if initialNumberOfActiveConnections != expectedInitialConnectionCount {
		testingContext.Errorf(
			"Expected %d initial connections, got %d",
			expectedInitialConnectionCount,
			initialNumberOfActiveConnections,
		)
	}

	connectionIdentifierForFirstConnection := "test-connection-001"
	
	contextForConnectionLifecycle, cancellationFunction := context.WithCancel(context.Background())
	defer cancellationFunction()

	messageChannelForOutgoingMessages := make(chan []byte, 10)
	defer close(messageChannelForOutgoingMessages)

	mockWebSocketConnection := (*websocket.Conn)(nil)

	firstClientConnection := &WebSocketClientConnection{
		uniqueConnectionIdentifierForThisClient:                        connectionIdentifierForFirstConnection,
		underlyingWebSocketConnectionToRemoteClient:                    mockWebSocketConnection,
		messageChannelForOutgoingMessagesToClient:                      messageChannelForOutgoingMessages,
		contextForCancellationOfAllConnectionOperations:                contextForConnectionLifecycle,
		cancellationFunctionToStopAllConnectionOperations:              cancellationFunction,
		hasConnectionBeenClosedAndCleanedUp:                            false,
		timestampOfLastSuccessfulMessageReceiptFromClient:              time.Now(),
		timestampOfMostRecentActivityOnThisConnection:                  time.Now(),
		totalNumberOfMessagesReceivedFromClientDuringLifetime:          0,
		totalNumberOfMessagesSuccessfullySentToClientDuringLifetime:    0,
		totalNumberOfErrorsEncounteredDuringConnectionLifetime:         0,
	}

	webSocketConnectionManager.registerNewClientConnectionInActiveConnectionsMap(firstClientConnection)

	numberOfConnectionsAfterRegistration := webSocketConnectionManager.GetTotalNumberOfActiveConnections()
	expectedConnectionCountAfterRegistration := 1

	if numberOfConnectionsAfterRegistration != expectedConnectionCountAfterRegistration {
		testingContext.Errorf(
			"Expected %d connections after registration, got %d",
			expectedConnectionCountAfterRegistration,
			numberOfConnectionsAfterRegistration,
		)
	}

	webSocketConnectionManager.unregisterAndCleanUpClientConnection(connectionIdentifierForFirstConnection)

	numberOfConnectionsAfterUnregistration := webSocketConnectionManager.GetTotalNumberOfActiveConnections()
	expectedConnectionCountAfterUnregistration := 0

	if numberOfConnectionsAfterUnregistration != expectedConnectionCountAfterUnregistration {
		testingContext.Errorf(
			"Expected %d connections after unregistration, got %d",
			expectedConnectionCountAfterUnregistration,
			numberOfConnectionsAfterUnregistration,
		)
	}

	testingContext.Log("Connection tracking test completed successfully")
}

func TestWebSocketMessageEnvelopeStructureJsonSerialization(testingContext *testing.T) {
	uniqueRequestIdentifier := "envelope-test-request-789"
	
	requestPayloadStructure := map[string]interface{}{
		"method": "test_method",
		"params": map[string]interface{}{
			"parameter_one": "value_one",
			"parameter_two": 42,
		},
	}

	requestPayloadAsJsonBytes, errorFromMarshalingRequestPayload := json.Marshal(requestPayloadStructure)
	
	if errorFromMarshalingRequestPayload != nil {
		testingContext.Fatal("Failed to marshal request payload:", errorFromMarshalingRequestPayload)
	}

	messageEnvelope := WebSocketMessageEnvelopeForModelContextProtocol{
		MessageTypeIdentifierString:                    "request",
		MessageIdentifierForRequestResponseCorrelation: uniqueRequestIdentifier,
		ModelContextProtocolRequestPayload:             requestPayloadAsJsonBytes,
	}

	envelopeAsJsonBytes, errorFromMarshalingEnvelope := json.Marshal(messageEnvelope)
	
	if errorFromMarshalingEnvelope != nil {
		testingContext.Fatal("Failed to marshal envelope:", errorFromMarshalingEnvelope)
	}

	var deserializedEnvelope WebSocketMessageEnvelopeForModelContextProtocol
	
	errorFromUnmarshalingEnvelope := json.Unmarshal(envelopeAsJsonBytes, &deserializedEnvelope)

	if errorFromUnmarshalingEnvelope != nil {
		testingContext.Fatal("Failed to unmarshal envelope:", errorFromUnmarshalingEnvelope)
	}

	deserializedMessageType := deserializedEnvelope.MessageTypeIdentifierString
	expectedMessageType := "request"
	
	if deserializedMessageType != expectedMessageType {
		testingContext.Errorf(
			"Message type mismatch: expected '%s', got '%s'",
			expectedMessageType,
			deserializedMessageType,
		)
	}

	deserializedRequestIdentifier := deserializedEnvelope.MessageIdentifierForRequestResponseCorrelation
	
	if deserializedRequestIdentifier != uniqueRequestIdentifier {
		testingContext.Errorf(
			"Request ID mismatch: expected '%s', got '%s'",
			uniqueRequestIdentifier,
			deserializedRequestIdentifier,
		)
	}

	var deserializedRequestPayload map[string]interface{}
	
	errorFromUnmarshalingRequestPayload := json.Unmarshal(
		deserializedEnvelope.ModelContextProtocolRequestPayload,
		&deserializedRequestPayload,
	)

	if errorFromUnmarshalingRequestPayload != nil {
		testingContext.Fatal("Failed to unmarshal request payload:", errorFromUnmarshalingRequestPayload)
	}

	methodNameFromDeserializedPayload, methodNameExists := deserializedRequestPayload["method"].(string)
	
	if !methodNameExists {
		testingContext.Fatal("Request payload missing 'method' field")
	}

	expectedMethodName := "test_method"
	
	if methodNameFromDeserializedPayload != expectedMethodName {
		testingContext.Errorf(
			"Method name mismatch: expected '%s', got '%s'",
			expectedMethodName,
			methodNameFromDeserializedPayload,
		)
	}

	testingContext.Log("Message envelope serialization test completed successfully")
}
