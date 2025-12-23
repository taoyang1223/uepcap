// Package moonshot provides a client for the Moonshot (Kimi) Chat API
// API Documentation: https://platform.moonshot.cn/docs/api/chat
package moonshot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Client is a Moonshot API client
type Client struct {
	apiKey     string
	baseURL    string
	model      string
	httpClient *http.Client
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

// StreamDelta represents a delta in streaming response
type StreamDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// StreamChoice represents a choice in streaming response
type StreamChoice struct {
	Index        int         `json:"index"`
	Delta        StreamDelta `json:"delta"`
	FinishReason string      `json:"finish_reason,omitempty"`
}

// StreamResponse represents a streaming chat completion response chunk
type StreamResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []StreamChoice `json:"choices"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"` // "system", "user", "assistant"
	Content string `json:"content"`
}

// ChatResponse represents a chat completion response
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Choice represents a response choice
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage represents token usage
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ErrorResponse represents an API error
type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// NewClient creates a new Moonshot client
func NewClient(apiKey, baseURL string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		// Default model (can be overridden by caller via SetModel)
		model: "kimi-k2-turbo-preview",
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // Long timeout for large context
		},
	}
}

// SetModel sets the model to use
func (c *Client) SetModel(model string) {
	c.model = model
}

// truncateString truncates a string to maxLen chars, adding "..." if truncated
func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	// Replace newlines with spaces for single-line logging
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	// Collapse multiple spaces
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ChatCompletion sends a chat completion request and returns the assistant's response
func (c *Client) ChatCompletion(ctx context.Context, userPrompt string) (string, error) {
	return c.ChatCompletionWithSystem(ctx, "", userPrompt)
}

// ChatCompletionWithSystem sends a chat completion request with a system prompt
func (c *Client) ChatCompletionWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	messages := []Message{}

	if systemPrompt != "" {
		messages = append(messages, Message{
			Role:    "system",
			Content: systemPrompt,
		})
	}

	messages = append(messages, Message{
		Role:    "user",
		Content: userPrompt,
	})

	return c.ChatCompletionWithMessages(ctx, messages)
}

// ChatCompletionWithMessages sends a chat completion request with custom messages
func (c *Client) ChatCompletionWithMessages(ctx context.Context, messages []Message) (string, error) {
	reqBody := ChatRequest{
		Model:       c.model,
		Messages:    messages,
		Temperature: 0.3,   // Lower temperature for more consistent JSON output
		MaxTokens:   16384, // Ensure enough tokens for complete flow JSON output
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Log detailed input information
	log.Printf("[Moonshot] ========== LLM REQUEST START ==========")
	log.Printf("[Moonshot] Endpoint: %s/chat/completions", c.baseURL)
	log.Printf("[Moonshot] Model: %s, Temperature: %.2f, MaxTokens: %d", c.model, reqBody.Temperature, reqBody.MaxTokens)
	log.Printf("[Moonshot] Message count: %d, Total request size: %d bytes", len(messages), len(jsonData))
	for i, msg := range messages {
		contentPreview := truncateString(msg.Content, 500)
		log.Printf("[Moonshot] Message[%d] role=%s, content_len=%d, preview: %s",
			i, msg.Role, len(msg.Content), contentPreview)
	}
	log.Printf("[Moonshot] ========== LLM REQUEST END ============")

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Moonshot] HTTP request failed: %v", err)
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Moonshot] Received response, status: %d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Moonshot] Failed to read response body: %v", err)
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	log.Printf("[Moonshot] Response body size: %d bytes", len(body))

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
			log.Printf("[Moonshot] API error: %s (type: %s, code: %s)", errResp.Error.Message, errResp.Error.Type, errResp.Error.Code)
			return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, errResp.Error.Message)
		}
		log.Printf("[Moonshot] API error (raw): %s", string(body))
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		log.Printf("[Moonshot] Failed to parse response JSON: %v", err)
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Log detailed response information
	log.Printf("[Moonshot] ========== LLM RESPONSE START ==========")
	log.Printf("[Moonshot] Response ID: %s, Model: %s", chatResp.ID, chatResp.Model)
	log.Printf("[Moonshot] Token Usage: prompt=%d, completion=%d, total=%d",
		chatResp.Usage.PromptTokens, chatResp.Usage.CompletionTokens, chatResp.Usage.TotalTokens)
	log.Printf("[Moonshot] Choices count: %d", len(chatResp.Choices))

	if len(chatResp.Choices) == 0 {
		log.Printf("[Moonshot] ERROR: No choices in response")
		log.Printf("[Moonshot] ========== LLM RESPONSE END ============")
		return "", fmt.Errorf("no choices in response")
	}

	choice := chatResp.Choices[0]
	content := choice.Message.Content
	log.Printf("[Moonshot] Choice[0]: finish_reason=%s, content_length=%d",
		choice.FinishReason, len(content))

	// Log response content preview (first and last 300 chars)
	if len(content) > 0 {
		contentPreview := truncateString(content, 600)
		log.Printf("[Moonshot] Response content preview: %s", contentPreview)
		// Also log the last part if content is long
		if len(content) > 600 {
			lastPart := content[len(content)-300:]
			log.Printf("[Moonshot] Response content (last 300 chars): ...%s", lastPart)
		}
	}
	log.Printf("[Moonshot] ========== LLM RESPONSE END ============")

	// Check if response was truncated due to token limit
	if choice.FinishReason == "length" {
		log.Printf("[Moonshot] WARNING: Response truncated due to token limit")
		return "", fmt.Errorf("response was truncated due to token limit (used %d tokens)", chatResp.Usage.CompletionTokens)
	}

	return content, nil
}

// ChatCompletionStream sends a streaming chat completion request
// The callback is called for each content chunk received
func (c *Client) ChatCompletionStream(ctx context.Context, userPrompt string, callback func(chunk string) error) error {
	messages := []Message{
		{Role: "user", Content: userPrompt},
	}
	return c.ChatCompletionStreamWithMessages(ctx, messages, callback)
}

// ChatCompletionStreamWithMessages sends a streaming chat completion request with custom messages
func (c *Client) ChatCompletionStreamWithMessages(ctx context.Context, messages []Message, callback func(chunk string) error) error {
	reqBody := ChatRequest{
		Model:       c.model,
		Messages:    messages,
		Temperature: 0.3,
		MaxTokens:   16384,
		Stream:      true,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Log detailed streaming input information
	log.Printf("[Moonshot Stream] ========== LLM STREAM REQUEST START ==========")
	log.Printf("[Moonshot Stream] Endpoint: %s/chat/completions (streaming)", c.baseURL)
	log.Printf("[Moonshot Stream] Model: %s, Temperature: %.2f, MaxTokens: %d", c.model, reqBody.Temperature, reqBody.MaxTokens)
	log.Printf("[Moonshot Stream] Message count: %d, Total request size: %d bytes", len(messages), len(jsonData))
	for i, msg := range messages {
		contentPreview := truncateString(msg.Content, 500)
		log.Printf("[Moonshot Stream] Message[%d] role=%s, content_len=%d, preview: %s",
			i, msg.Role, len(msg.Content), contentPreview)
	}
	log.Printf("[Moonshot Stream] ========== LLM STREAM REQUEST END ============")

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Moonshot Stream] HTTP request failed: %v", err)
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Moonshot Stream] Received response, status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
			log.Printf("[Moonshot Stream] API error: %s", errResp.Error.Message)
			return fmt.Errorf("API error (status %d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse SSE stream
	reader := bufio.NewReader(resp.Body)
	var totalContent strings.Builder
	chunkCount := 0
	startTime := time.Now()

	log.Printf("[Moonshot Stream] ========== LLM STREAM RESPONSE START ==========")

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Moonshot Stream] Context cancelled after %v, received %d chunks, total content: %d bytes",
				time.Since(startTime), chunkCount, totalContent.Len())
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log.Printf("[Moonshot Stream] Stream EOF after %v, received %d chunks, total content: %d bytes",
					time.Since(startTime), chunkCount, totalContent.Len())
				logStreamResponseSummary(totalContent.String())
				return nil
			}
			return fmt.Errorf("failed to read stream: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// SSE format: "data: {...}"
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			log.Printf("[Moonshot Stream] Stream completed in %v, received %d chunks, total content: %d bytes",
				time.Since(startTime), chunkCount, totalContent.Len())
			logStreamResponseSummary(totalContent.String())
			log.Printf("[Moonshot Stream] ========== LLM STREAM RESPONSE END ============")
			return nil
		}

		var streamResp StreamResponse
		if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
			log.Printf("[Moonshot Stream] Failed to parse chunk: %v, data: %s", err, data)
			continue
		}

		if len(streamResp.Choices) > 0 {
			content := streamResp.Choices[0].Delta.Content
			if content != "" {
				chunkCount++
				totalContent.WriteString(content)
				if err := callback(content); err != nil {
					return fmt.Errorf("callback error: %w", err)
				}
			}

			if streamResp.Choices[0].FinishReason == "stop" {
				log.Printf("[Moonshot Stream] Stream finished with stop in %v, received %d chunks, total content: %d bytes",
					time.Since(startTime), chunkCount, totalContent.Len())
				logStreamResponseSummary(totalContent.String())
				log.Printf("[Moonshot Stream] ========== LLM STREAM RESPONSE END ============")
				return nil
			}
		}
	}
}

// logStreamResponseSummary logs a summary of the streamed response
func logStreamResponseSummary(content string) {
	if len(content) == 0 {
		log.Printf("[Moonshot Stream] Response content: (empty)")
		return
	}
	preview := truncateString(content, 600)
	log.Printf("[Moonshot Stream] Response content preview: %s", preview)
	if len(content) > 600 {
		lastPart := content
		if len(lastPart) > 300 {
			lastPart = content[len(content)-300:]
		}
		log.Printf("[Moonshot Stream] Response content (last 300 chars): ...%s", truncateString(lastPart, 300))
	}
}
