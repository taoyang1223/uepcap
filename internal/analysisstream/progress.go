package analysisstream

type Progress struct {
	ProcessedMessages int  `json:"processed_messages"`
	ChunkIndex        int  `json:"chunk_index"`
	ChunkMessages     int  `json:"chunk_messages"`
	ChunkTarget       int  `json:"chunk_target"`
	Done              bool `json:"done,omitempty"`
}
