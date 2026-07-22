package api

import "gitee.com/yangdadayyds/uepcap/internal/s11analyzer"

func annotateS11SourceFiles(result *s11analyzer.AnalysisResult, index *packetSourceIndex) {
	if result == nil || index == nil {
		return
	}
	sourceByFrame := make(map[int]string, len(result.Messages))
	for _, message := range result.Messages {
		message.SourceFile = index.lookup(message.Timestamp, message.SourceIP, message.DestinationIP)
		if message.SourceFile != "" {
			sourceByFrame[message.FrameNumber] = message.SourceFile
		}
	}
	for _, transaction := range result.Transactions {
		transaction.SourceFile = sourceByFrame[transaction.RequestFrame]
		transaction.ResponseFile = sourceByFrame[transaction.ResponseFrame]
	}
}
