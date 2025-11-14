package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

type WebSocketMessageEnvelopeForModelContextProtocol struct {
	MessageTypeIdentifierString                         string          `json:"type"`
	MessageIdentifierForRequestResponseCorrelation      string          `json:"id,omitempty"`
	ModelContextProtocolRequestPayload                  json.RawMessage `json:"request,omitempty"`
	ModelContextProtocolResponsePayload                 json.RawMessage `json:"response,omitempty"`
	ModelContextProtocolErrorPayload                    json.RawMessage `json:"error,omitempty"`
}

type ModelContextProtocolRequestStructure struct {
	MethodNameForRemoteProcedureCall  string                 `json:"method"`
	ParametersForMethodInvocation     map[string]interface{} `json:"params,omitempty"`
}

func demonstrateWebSocketConnectionToIdaHeadlessMcpServer() {
	interruptSignalChannelForGracefulShutdown := make(chan os.Signal, 1)
	signal.Notify(interruptSignalChannelForGracefulShutdown, os.Interrupt)

	webSocketServerUrlForConnection := "ws://localhost:17300/ws"
	
	logMessageIndicatingConnectionAttempt := fmt.Sprintf("Attempting to connect to IDA Headless MCP WebSocket server at: %s", webSocketServerUrlForConnection)
	log.Println(logMessageIndicatingConnectionAttempt)

	webSocketDialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	connectionToWebSocketServer, httpResponseFromHandshake, errorFromDialingWebSocket := webSocketDialer.Dial(
		webSocketServerUrlForConnection,
		nil,
	)

	if errorFromDialingWebSocket != nil {
		errorMessageDescribingConnectionFailure := fmt.Sprintf("Failed to establish WebSocket connection: %v", errorFromDialingWebSocket)
		log.Fatal(errorMessageDescribingConnectionFailure)
	}

	defer connectionToWebSocketServer.Close()

	if httpResponseFromHandshake != nil {
		httpStatusCodeFromHandshakeResponse := httpResponseFromHandshake.StatusCode
		logMessageIndicatingSuccessfulConnection := fmt.Sprintf("WebSocket connection established successfully, HTTP status code: %d", httpStatusCodeFromHandshakeResponse)
		log.Println(logMessageIndicatingSuccessfulConnection)
	}

	channelForReceivingMessagesFromServer := make(chan []byte)

	go continuouslyReadMessagesFromWebSocketServerInBackground(
		connectionToWebSocketServer,
		channelForReceivingMessagesFromServer,
	)

	uniqueRequestIdentifierForListToolsRequest := "request-list-tools-001"
	
	sendListToolsRequestToServerViaWebSocket(
		connectionToWebSocketServer,
		uniqueRequestIdentifierForListToolsRequest,
	)

	timeoutDurationForWaitingForResponse := 10 * time.Second
	timerForResponseTimeout := time.NewTimer(timeoutDurationForWaitingForResponse)

	numberOfResponsesReceivedFromServer := 0

	for {
		shouldContinueWaitingForMessages := true

		select {
		case <-interruptSignalChannelForGracefulShutdown:
			log.Println("Interrupt signal received, closing WebSocket connection gracefully")
			shouldContinueWaitingForMessages = false

		case messageDataBytesFromServer := <-channelForReceivingMessagesFromServer:
			numberOfResponsesReceivedFromServer = numberOfResponsesReceivedFromServer + 1
			
			logMessageIndicatingMessageReceipt := fmt.Sprintf("Received message #%d from server", numberOfResponsesReceivedFromServer)
			log.Println(logMessageIndicatingMessageReceipt)
			
			processReceivedMessageFromServerAndDisplayContent(messageDataBytesFromServer)

		case <-timerForResponseTimeout.C:
			log.Println("Timeout waiting for server response")
			shouldContinueWaitingForMessages = false
		}

		if !shouldContinueWaitingForMessages {
			break
		}

		maximumNumberOfResponsesToReceiveBeforeExiting := 1
		hasReceivedExpectedNumberOfResponses := numberOfResponsesReceivedFromServer >= maximumNumberOfResponsesToReceiveBeforeExiting
		
		if hasReceivedExpectedNumberOfResponses {
			break
		}
	}

	closeMessagePayload := websocket.FormatCloseMessage(
		websocket.CloseNormalClosure,
		"Client demonstration complete",
	)
	
	writeTimeoutDurationForCloseMessage := 5 * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	closeMessageWriteDeadline := currentTimeForDeadlineCalculation.Add(writeTimeoutDurationForCloseMessage)
	
	connectionToWebSocketServer.SetWriteDeadline(closeMessageWriteDeadline)
	
	errorFromWritingCloseMessage := connectionToWebSocketServer.WriteMessage(
		websocket.CloseMessage,
		closeMessagePayload,
	)

	if errorFromWritingCloseMessage != nil {
		logMessageIndicatingCloseError := fmt.Sprintf("Error sending close message: %v", errorFromWritingCloseMessage)
		log.Println(logMessageIndicatingCloseError)
	}

	log.Println("WebSocket demonstration completed successfully")
}

func continuouslyReadMessagesFromWebSocketServerInBackground(
	webSocketConnectionToReadFrom *websocket.Conn,
	channelForForwardingReceivedMessages chan []byte,
) {
	for {
		messageTypeFromWebSocket, messageDataBytesReceived, errorFromReadingMessage := webSocketConnectionToReadFrom.ReadMessage()

		if errorFromReadingMessage != nil {
			errorMessageDescribingReadFailure := fmt.Sprintf("WebSocket read error: %v", errorFromReadingMessage)
			log.Println(errorMessageDescribingReadFailure)
			close(channelForForwardingReceivedMessages)
			break
		}

		messageIsTextType := messageTypeFromWebSocket == websocket.TextMessage
		messageIsBinaryType := messageTypeFromWebSocket == websocket.BinaryMessage

		if messageIsTextType || messageIsBinaryType {
			channelForForwardingReceivedMessages <- messageDataBytesReceived
		}
	}
}

func sendListToolsRequestToServerViaWebSocket(
	webSocketConnectionForSending *websocket.Conn,
	requestIdentifierForCorrelation string,
) {
	modelContextProtocolRequestForListingTools := ModelContextProtocolRequestStructure{
		MethodNameForRemoteProcedureCall: "tools/list",
		ParametersForMethodInvocation:    map[string]interface{}{},
	}

	requestPayloadAsJsonBytes, errorFromMarshalingRequest := json.Marshal(modelContextProtocolRequestForListingTools)

	if errorFromMarshalingRequest != nil {
		errorMessageDescribingMarshalingFailure := fmt.Sprintf("Failed to marshal request payload: %v", errorFromMarshalingRequest)
		log.Fatal(errorMessageDescribingMarshalingFailure)
	}

	messageEnvelopeForRequest := WebSocketMessageEnvelopeForModelContextProtocol{
		MessageTypeIdentifierString:                    "request",
		MessageIdentifierForRequestResponseCorrelation: requestIdentifierForCorrelation,
		ModelContextProtocolRequestPayload:             requestPayloadAsJsonBytes,
	}

	envelopeAsJsonBytes, errorFromMarshalingEnvelope := json.Marshal(messageEnvelopeForRequest)

	if errorFromMarshalingEnvelope != nil {
		errorMessageDescribingEnvelopeMarshalingFailure := fmt.Sprintf("Failed to marshal message envelope: %v", errorFromMarshalingEnvelope)
		log.Fatal(errorMessageDescribingEnvelopeMarshalingFailure)
	}

	writeTimeoutDurationForMessage := 10 * time.Second
	currentTimeForDeadlineCalculation := time.Now()
	writeDeadlineForMessage := currentTimeForDeadlineCalculation.Add(writeTimeoutDurationForMessage)
	
	webSocketConnectionForSending.SetWriteDeadline(writeDeadlineForMessage)

	errorFromWritingMessage := webSocketConnectionForSending.WriteMessage(
		websocket.TextMessage,
		envelopeAsJsonBytes,
	)

	if errorFromWritingMessage != nil {
		errorMessageDescribingWriteFailure := fmt.Sprintf("Failed to send WebSocket message: %v", errorFromWritingMessage)
		log.Fatal(errorMessageDescribingWriteFailure)
	}

	messageSizeInBytes := len(envelopeAsJsonBytes)
	logMessageIndicatingSuccessfulSend := fmt.Sprintf("Sent request to server, size: %d bytes, request ID: %s", messageSizeInBytes, requestIdentifierForCorrelation)
	log.Println(logMessageIndicatingSuccessfulSend)
}

func processReceivedMessageFromServerAndDisplayContent(
	messageDataBytesReceivedFromServer []byte,
) {
	var parsedMessageEnvelope WebSocketMessageEnvelopeForModelContextProtocol

	errorFromUnmarshalingMessage := json.Unmarshal(messageDataBytesReceivedFromServer, &parsedMessageEnvelope)

	if errorFromUnmarshalingMessage != nil {
		errorMessageDescribingParseFailure := fmt.Sprintf("Failed to parse server message: %v", errorFromUnmarshalingMessage)
		log.Println(errorMessageDescribingParseFailure)
		return
	}

	messageTypeString := parsedMessageEnvelope.MessageTypeIdentifierString
	messageIdentifier := parsedMessageEnvelope.MessageIdentifierForRequestResponseCorrelation

	logMessageDescribingReceivedMessageType := fmt.Sprintf("Received message type: %s, ID: %s", messageTypeString, messageIdentifier)
	log.Println(logMessageDescribingReceivedMessageType)

	messageIsResponseType := messageTypeString == "response"
	messageIsErrorType := messageTypeString == "error"

	if messageIsResponseType {
		responsePayloadAsRawJson := parsedMessageEnvelope.ModelContextProtocolResponsePayload
		
		var responseDataAsGenericMap map[string]interface{}
		errorFromParsingResponsePayload := json.Unmarshal(responsePayloadAsRawJson, &responseDataAsGenericMap)

		if errorFromParsingResponsePayload != nil {
			errorMessageDescribingResponseParseFailure := fmt.Sprintf("Failed to parse response payload: %v", errorFromParsingResponsePayload)
			log.Println(errorMessageDescribingResponseParseFailure)
			return
		}

		responsePayloadFormattedAsJson, _ := json.MarshalIndent(responseDataAsGenericMap, "", "  ")
		formattedJsonAsString := string(responsePayloadFormattedAsJson)
		
		log.Printf("Response payload:\n%s", formattedJsonAsString)
	}

	if messageIsErrorType {
		errorPayloadAsRawJson := parsedMessageEnvelope.ModelContextProtocolErrorPayload
		
		var errorDataAsGenericMap map[string]interface{}
		errorFromParsingErrorPayload := json.Unmarshal(errorPayloadAsRawJson, &errorDataAsGenericMap)

		if errorFromParsingErrorPayload != nil {
			errorMessageDescribingErrorPayloadParseFailure := fmt.Sprintf("Failed to parse error payload: %v", errorFromParsingErrorPayload)
			log.Println(errorMessageDescribingErrorPayloadParseFailure)
			return
		}

		errorPayloadFormattedAsJson, _ := json.MarshalIndent(errorDataAsGenericMap, "", "  ")
		formattedJsonAsString := string(errorPayloadFormattedAsJson)
		
		log.Printf("Error payload:\n%s", formattedJsonAsString)
	}
}

func main() {
	demonstrateWebSocketConnectionToIdaHeadlessMcpServer()
}
