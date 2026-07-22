package api

import (
	"gitee.com/yangdadayyds/uepcap/internal/nasanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
	"gitee.com/yangdadayyds/uepcap/internal/s1apanalyzer"
)

func annotateNGAPSourceFiles(result *ngapanalyzer.AnalysisResult, index *packetSourceIndex) {
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
		transaction.SourceFile = sourceByFrame[transaction.StartFrame]
		transaction.ResponseFile = sourceByFrame[transaction.EndFrame]
		for i := range transaction.Steps {
			transaction.Steps[i].SourceFile = sourceByFrame[transaction.Steps[i].FrameNumber]
		}
	}
}

func annotateS1APSourceFiles(result *s1apanalyzer.AnalysisResult, index *packetSourceIndex) {
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
		transaction.SourceFile = sourceByFrame[transaction.StartFrame]
		transaction.ResponseFile = sourceByFrame[transaction.EndFrame]
		for i := range transaction.Steps {
			transaction.Steps[i].SourceFile = sourceByFrame[transaction.Steps[i].FrameNumber]
		}
	}
}

func annotateNASSourceFiles(result *nasanalyzer.AnalysisResult, index *packetSourceIndex) {
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
	for _, flow := range result.Flows {
		flow.SourceFile = sourceByFrame[flow.StartFrame]
		flow.ResponseFile = sourceByFrame[flow.EndFrame]
		for i := range flow.Steps {
			flow.Steps[i].SourceFile = sourceByFrame[flow.Steps[i].FrameNumber]
		}
	}
}

func annotatePFCPSourceFiles(result *pfcpsession.AnalysisResult, index *packetSourceIndex) {
	if result == nil || index == nil {
		return
	}
	for _, transaction := range result.Transactions {
		transaction.SourceFile = index.lookup(transaction.RequestTime, transaction.SourceIP, transaction.DestinationIP)
		if transaction.ResponseTime != nil {
			transaction.ResponseFile = index.lookup(*transaction.ResponseTime, transaction.DestinationIP, transaction.SourceIP)
		}
	}
}
