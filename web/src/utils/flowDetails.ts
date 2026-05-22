/**
 * Flow Details Utility
 * 
 * Derives rich details (title, detail_lines, fields) from CompactPacket JSON.
 * Used for frontend-derived summaries in the flow viewer.
 */

// CompactPacket structure matches backend packet.CompactPacket
export interface CompactPacket {
  frame: {
    number: string
    time: string
    time_absolute: string
    len: string
    protocols: string
  }
  layers: {
    src_ip?: string
    dst_ip?: string
    src_port?: string
    dst_port?: string
    proto?: string
  }
  application?: Record<string, ApplicationInfo>
}

// ApplicationInfo is a flexible structure for different protocol types
export interface ApplicationInfo {
  // Common fields
  procedure?: string
  procedureCode?: string
  pduType?: string
  message?: string
  message_type?: string
  
  // NAS fields
  mm_message?: string
  mm_message_type?: string
  sm_message?: string
  sm_message_type?: string
  dnn?: string
  pdu_session_id?: string
  ue_ipv4?: string
  ue_ipv6?: string
  sst?: string
  sd?: string
  qfi?: string
  msin?: string
  mcc?: string
  mnc?: string
  supi?: string
  reg_type?: string
  '5g_guti'?: string
  
  // PFCP fields
  seid?: string
  
  // GTP fields
  teid?: string
  
  // Nested structures
  nas?: ApplicationInfo
  ies?: Record<string, unknown>
  
  // Allow other fields
  [key: string]: unknown
}

// FlowDetailMapping is the minimal mapping from backend
export interface FlowDetailMapping {
  idx: number
  frame: number
  originNumber: string
}

// PacketColumns holds wireshark column display values for a packet.
// These are the same values displayed in Wireshark's packet list,
// extracted by tshark on the backend.
export interface PacketColumns {
  frame_number: string
  time_relative: string
  source: string
  destination: string
  protocol: string
  length: string
  info: string        // Original _ws.col.Info
  info_clean: string  // Info with SACK prefix removed
}

// MappingEntry represents a single idx:frameNumber mapping entry
export interface MappingEntry {
  idx: number
  frameNumber: string
}

// IPMapping maps an IP address to a network element role (from protocol-based inference)
export interface IPMapping {
  ip: string
  ne: string  // gNB, AMF, SMF, UPF, etc.
  confidence?: number
  reason?: string
}

// FlowAnnotationsV1 is the structured JSON for IP→NE mapping annotations
export interface FlowAnnotationsV1 {
  version: string
  flow_name?: string
  ip_map: IPMapping[]
  stages?: Array<{
    name: string
    summary?: string
    frames: Array<{
      number: string
      title?: string
      note?: string
    }>
  }>
}

// RichFlowDetail is the derived detail for UI display
export interface RichFlowDetail {
  idx: number
  frame: number
  originNumber: string
  from?: string
  to?: string
  protocol?: string
  title: string
  detail_lines: string[]
  fields: Record<string, unknown>
}

// Protocol name mappings for human-readable titles
const NGAP_PROCEDURES: Record<string, string> = {
  '0': 'AMFConfigurationUpdate',
  '4': 'DownlinkNASTransport',
  '14': 'InitialContextSetup',
  '15': 'InitialUEMessage',
  '26': 'PDUSessionResourceModify',
  '28': 'PDUSessionResourceRelease',
  '29': 'PDUSessionResourceSetup',
  '40': 'UEContextModification',
  '41': 'UEContextRelease',
  '46': 'UplinkNASTransport',
}

const NAS_5GMM_MESSAGES: Record<string, string> = {
  '0x41': 'Registration Request',
  '0x42': 'Registration Accept',
  '0x43': 'Registration Complete',
  '0x44': 'Registration Reject',
  '0x45': 'Deregistration Request (UE)',
  '0x46': 'Deregistration Accept (UE)',
  '0x4d': 'Service Reject',
  '0x56': 'Authentication Request',
  '0x57': 'Authentication Response',
  '0x5d': 'Security Mode Command',
  '0x5e': 'Security Mode Complete',
  '0x67': 'UL NAS Transport',
  '0x68': 'DL NAS Transport',
}

const NAS_5GSM_MESSAGES: Record<string, string> = {
  '0xc1': 'PDU Session Establishment Request',
  '0xc2': 'PDU Session Establishment Accept',
  '0xc3': 'PDU Session Establishment Reject',
  '0xc9': 'PDU Session Modification Request',
  '0xca': 'PDU Session Modification Reject',
  '0xcb': 'PDU Session Modification Command',
  '0xd1': 'PDU Session Release Request',
  '0xd3': 'PDU Session Release Command',
}

const PFCP_MESSAGES: Record<string, string> = {
  '1': 'Heartbeat Request',
  '2': 'Heartbeat Response',
  '5': 'Association Setup Request',
  '6': 'Association Setup Response',
  '7': 'Association Update Request',
  '8': 'Association Update Response',
  '9': 'Association Release Request',
  '10': 'Association Release Response',
  '12': 'Node Report Request',
  '13': 'Node Report Response',
  '50': 'Session Establishment Request',
  '51': 'Session Establishment Response',
  '52': 'Session Modification Request',
  '53': 'Session Modification Response',
  '54': 'Session Deletion Request',
  '55': 'Session Deletion Response',
  '56': 'Session Report Request',
  '57': 'Session Report Response',
}

const GTPV2_MESSAGES: Record<string, string> = {
  '1': 'Echo Request',
  '2': 'Echo Response',
  '32': 'Create Session Request',
  '33': 'Create Session Response',
  '34': 'Modify Bearer Request',
  '35': 'Modify Bearer Response',
  '36': 'Delete Session Request',
  '37': 'Delete Session Response',
}

/**
 * Infers the network element role from IP address and port (legacy, without annotations)
 * DEPRECATED: Use getDisplayNameForIP when annotations are available
 */
function inferRole(ip: string | undefined, port: string | undefined, proto: string | undefined): string {
  if (!ip) return '?'
  
  // SCTP port 38412 is typically NGAP (gNB <-> AMF)
  if (proto === 'sctp' && port === '38412') {
    return 'AMF'
  }
  
  // UDP port 8805 is typically PFCP (SMF <-> UPF)
  if (proto === 'udp' && port === '8805') {
    return 'SMF/UPF'
  }
  
  // UDP port 2123 is typically GTPv2-C
  if (proto === 'udp' && port === '2123') {
    return 'SGW/PGW'
  }
  
  // Return IP as fallback
  return ip
}

/**
 * Builds IP→NE lookup map from annotations
 */
function buildIPMaps(annotations: FlowAnnotationsV1 | null | undefined): {
  ipToNE: Map<string, string>
  roleCounts: Map<string, number>
} {
  const ipToNE = new Map<string, string>()
  const roleCounts = new Map<string, number>()
  
  if (annotations?.ip_map) {
    for (const mapping of annotations.ip_map) {
      if (mapping.ip && mapping.ne && mapping.ne !== 'Unknown') {
        ipToNE.set(mapping.ip, mapping.ne)
      }
    }
    
    // Count IPs per role
    for (const ne of ipToNE.values()) {
      roleCounts.set(ne, (roleCounts.get(ne) || 0) + 1)
    }
  }
  
  return { ipToNE, roleCounts }
}

/**
 * Gets the primary protocol name from application layer
 */
function getPrimaryProtocol(app: Record<string, ApplicationInfo> | undefined): string | undefined {
  if (!app) return undefined
  
  // Priority order
  const protocolOrder = ['ngap', 'nas-5gs', 'pfcp', 's1ap', 'gtpv2', 'gtp']
  for (const proto of protocolOrder) {
    if (app[proto]) return proto
  }
  
  // Return first available
  return Object.keys(app)[0]
}

/**
 * Generates a human-readable title for a packet
 */
function generateTitle(packet: CompactPacket): string {
  const app = packet.application
  if (!app) {
    return `Frame ${packet.frame.number}`
  }
  
  // NGAP
  if (app.ngap) {
    const ngap = app.ngap
    const proc = ngap.procedure || NGAP_PROCEDURES[ngap.procedureCode || ''] || 'NGAP'
    
    // Check for nested NAS message
    const nas = ngap.nas
    if (nas) {
      const mmMsg = nas.mm_message || NAS_5GMM_MESSAGES[nas.mm_message_type || '']
      const smMsg = nas.sm_message || NAS_5GSM_MESSAGES[nas.sm_message_type || '']
      if (mmMsg) return `${proc} (${mmMsg})`
      if (smMsg) return `${proc} (${smMsg})`
    }
    
    return proc
  }
  
  // NAS-5GS (standalone)
  if (app['nas-5gs']) {
    const nas = app['nas-5gs']
    const mmMsg = nas.mm_message || NAS_5GMM_MESSAGES[nas.mm_message_type || '']
    const smMsg = nas.sm_message || NAS_5GSM_MESSAGES[nas.sm_message_type || '']
    return mmMsg || smMsg || 'NAS-5GS'
  }
  
  // PFCP
  if (app.pfcp) {
    const pfcp = app.pfcp
    const msg = pfcp.message || PFCP_MESSAGES[pfcp.message_type || ''] || 'PFCP'
    return msg
  }
  
  // GTPv2
  if (app.gtpv2) {
    const gtp = app.gtpv2
    const msg = gtp.message || GTPV2_MESSAGES[gtp.message_type || ''] || 'GTPv2'
    return msg
  }
  
  // S1AP
  if (app.s1ap) {
    return app.s1ap.procedure || 'S1AP'
  }
  
  // GTP-U
  if (app.gtp) {
    return 'GTP-U Data'
  }
  
  return `Frame ${packet.frame.number}`
}

/**
 * Generates detail lines summarizing key fields
 */
function generateDetailLines(packet: CompactPacket): string[] {
  const lines: string[] = []
  const app = packet.application
  
  // Add frame info
  lines.push(`Frame: ${packet.frame.number}`)
  lines.push(`Time: ${packet.frame.time}`)
  
  // Add layer info
  if (packet.layers.src_ip && packet.layers.dst_ip) {
    lines.push(`${packet.layers.src_ip} → ${packet.layers.dst_ip}`)
  }
  
  if (!app) return lines
  
  // Extract key fields from each protocol
  const extractFields = (info: ApplicationInfo, prefix = '') => {
    // NAS fields
    if (info.supi) lines.push(`${prefix}SUPI: ${info.supi}`)
    if (info.msin && info.mcc && info.mnc) {
      lines.push(`${prefix}IMSI: ${info.mcc}${info.mnc}${info.msin}`)
    }
    if (info.dnn) lines.push(`${prefix}DNN: ${info.dnn}`)
    if (info.pdu_session_id) lines.push(`${prefix}PDU Session ID: ${info.pdu_session_id}`)
    if (info.ue_ipv4) lines.push(`${prefix}UE IPv4: ${info.ue_ipv4}`)
    if (info.ue_ipv6) lines.push(`${prefix}UE IPv6: ${info.ue_ipv6}`)
    if (info.sst) lines.push(`${prefix}SST: ${info.sst}`)
    if (info.sd) lines.push(`${prefix}SD: ${info.sd}`)
    if (info.qfi) lines.push(`${prefix}QFI: ${info.qfi}`)
    if (info['5g_guti']) lines.push(`${prefix}5G-GUTI: ${info['5g_guti']}`)
    if (info.reg_type) lines.push(`${prefix}Registration Type: ${info.reg_type}`)
    
    // PFCP/GTP fields
    if (info.seid) lines.push(`${prefix}SEID: ${info.seid}`)
    if (info.teid) lines.push(`${prefix}TEID: ${info.teid}`)
    
    // Nested NAS
    if (info.nas) {
      extractFields(info.nas, 'NAS ')
    }
  }
  
  for (const protoInfo of Object.values(app)) {
    extractFields(protoInfo)
  }
  
  return lines
}

/**
 * Generates fields object for expandable details
 */
function generateFields(packet: CompactPacket): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    frame: {
      number: packet.frame.number,
      time: packet.frame.time,
      protocols: packet.frame.protocols,
    },
    layers: packet.layers,
  }
  
  if (packet.application) {
    fields.application = packet.application
  }
  
  return fields
}

/**
 * Derives rich flow details from packets and mapping
 * @param inputJSON - The compact packet JSON string
 * @param detailsMap - The mapping from backend
 * @param annotations - Optional annotations for IP→NE mapping (aligns with diagram)
 */
export function deriveFlowDetails(
  inputJSON: string,
  detailsMap: FlowDetailMapping[],
  annotations?: FlowAnnotationsV1 | null
): RichFlowDetail[] {
  let packets: CompactPacket[]
  try {
    packets = JSON.parse(inputJSON) as CompactPacket[]
  } catch {
    console.error('[flowDetails] Failed to parse inputJSON')
    return []
  }
  
  // Build a map from originNumber to packet for quick lookup
  const packetByOrigin = new Map<string, CompactPacket>()
  for (const pkt of packets) {
    packetByOrigin.set(pkt.frame.number, pkt)
  }
  
  // Also build by array index (1-based)
  const packetByIndex = new Map<number, CompactPacket>()
  packets.forEach((pkt, i) => {
    packetByIndex.set(i + 1, pkt)
  })
  
  // Build IP maps for annotations-based naming
  const ipMaps = annotations ? buildIPMaps(annotations) : null
  
  // Track role sequence numbers for consistent naming
  // Note: In details list, we don't need sequential numbering across items
  // since each detail is independent. Use a simple approach.
  
  return detailsMap.map((mapping) => {
    // Try to find packet by originNumber first, then by frame index
    const packet = packetByOrigin.get(mapping.originNumber) || packetByIndex.get(mapping.frame)
    
    if (!packet) {
      return {
        idx: mapping.idx,
        frame: mapping.frame,
        originNumber: mapping.originNumber,
        title: `Frame ${mapping.originNumber}`,
        detail_lines: [],
        fields: {},
      }
    }
    
    const protocol = getPrimaryProtocol(packet.application)
    
    // Get from/to using annotations if available
    const srcIP = packet.layers.src_ip
    const dstIP = packet.layers.dst_ip
    let from: string, to: string
    
    if (ipMaps && ipMaps.ipToNE.size > 0) {
      // Use annotations: simple display without sequence numbers for detail list
      const srcRole = ipMaps.ipToNE.get(srcIP || '') || 'Unknown'
      const dstRole = ipMaps.ipToNE.get(dstIP || '') || 'Unknown'
      from = srcRole === 'Unknown' ? (srcIP || '?') : `${srcRole}(${srcIP})`
      to = dstRole === 'Unknown' ? (dstIP || '?') : `${dstRole}(${dstIP})`
    } else {
      // Fallback to legacy inference
      from = inferRole(srcIP, packet.layers.src_port, packet.layers.proto)
      to = inferRole(dstIP, packet.layers.dst_port, packet.layers.proto)
    }
    
    return {
      idx: mapping.idx,
      frame: mapping.frame,
      originNumber: mapping.originNumber,
      from,
      to,
      protocol,
      title: generateTitle(packet),
      detail_lines: generateDetailLines(packet),
      fields: generateFields(packet),
    }
  })
}

/**
 * Finds a packet by originNumber in the input JSON
 */
export function findPacketByOriginNumber(
  inputJSON: string,
  originNumber: string
): CompactPacket | undefined {
  try {
    const packets = JSON.parse(inputJSON) as CompactPacket[]
    return packets.find((pkt) => pkt.frame.number === originNumber)
  } catch {
    return undefined
  }
}

/**
 * Parses the MAPPING section from stream content.
 * Format: each line is "idx:frameNumber" (e.g., "1:1001")
 */
export function parseMapping(streamContent: string): MappingEntry[] {
  const mapping: MappingEntry[] = []
  
  const mappingMarker = '---MAPPING---'
  const mappingIdx = streamContent.indexOf(mappingMarker)
  if (mappingIdx === -1) {
    return mapping
  }
  
  let rest = streamContent.slice(mappingIdx + mappingMarker.length).trim()
  
  // Find end of mapping section (next --- marker or end of string)
  const nextMarkerIdx = rest.indexOf('---')
  if (nextMarkerIdx !== -1) {
    rest = rest.slice(0, nextMarkerIdx)
  }
  
  // Parse each line
  const lines = rest.split('\n')
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    
    const parts = trimmed.split(':')
    if (parts.length !== 2) continue
    
    const idx = parseInt(parts[0].trim(), 10)
    const frameNumber = parts[1].trim()
    
    if (!isNaN(idx) && frameNumber) {
      mapping.push({ idx, frameNumber })
    }
  }
  
  return mapping
}

/**
 * Derives rich flow details from packets using the provided mapping.
 * This provides accurate correlation when heartbeat messages are skipped.
 * @param inputJSON - The compact packet JSON string
 * @param mapping - The frame number mapping
 * @param annotations - Optional annotations for IP→NE mapping (aligns with diagram)
 */
export function deriveFlowDetailsFromMapping(
  inputJSON: string,
  mapping: MappingEntry[],
  annotations?: FlowAnnotationsV1 | null
): RichFlowDetail[] {
  let packets: CompactPacket[]
  try {
    packets = JSON.parse(inputJSON) as CompactPacket[]
  } catch {
    console.error('[flowDetails] Failed to parse inputJSON')
    return []
  }
  
  // Build a map from frame.number to packet for quick lookup
  const packetByFrameNumber = new Map<string, CompactPacket>()
  const frameNumberToArrayIdx = new Map<string, number>()
  for (let i = 0; i < packets.length; i++) {
    const pkt = packets[i]
    packetByFrameNumber.set(pkt.frame.number, pkt)
    frameNumberToArrayIdx.set(pkt.frame.number, i + 1) // 1-based
  }
  
  // Build IP maps for annotations-based naming
  const ipMaps = annotations ? buildIPMaps(annotations) : null
  
  return mapping.map((entry) => {
    const packet = packetByFrameNumber.get(entry.frameNumber)
    const arrayIdx = frameNumberToArrayIdx.get(entry.frameNumber) || entry.idx
    
    if (!packet) {
      return {
        idx: entry.idx,
        frame: arrayIdx,
        originNumber: entry.frameNumber,
        title: `Frame ${entry.frameNumber}`,
        detail_lines: [],
        fields: {},
      }
    }
    
    const protocol = getPrimaryProtocol(packet.application)
    
    // Get from/to using annotations if available
    const srcIP = packet.layers.src_ip
    const dstIP = packet.layers.dst_ip
    let from: string, to: string
    
    if (ipMaps && ipMaps.ipToNE.size > 0) {
      // Use annotations: simple display without sequence numbers for detail list
      const srcRole = ipMaps.ipToNE.get(srcIP || '') || 'Unknown'
      const dstRole = ipMaps.ipToNE.get(dstIP || '') || 'Unknown'
      from = srcRole === 'Unknown' ? (srcIP || '?') : `${srcRole}(${srcIP})`
      to = dstRole === 'Unknown' ? (dstIP || '?') : `${dstRole}(${dstIP})`
    } else {
      // Fallback to legacy inference
      from = inferRole(srcIP, packet.layers.src_port, packet.layers.proto)
      to = inferRole(dstIP, packet.layers.dst_port, packet.layers.proto)
    }
    
    return {
      idx: entry.idx,
      frame: arrayIdx,
      originNumber: entry.frameNumber,
      from,
      to,
      protocol,
      title: generateTitle(packet),
      detail_lines: generateDetailLines(packet),
      fields: generateFields(packet),
    }
  })
}

/**
 * Derives rich flow details using tshark-extracted packet columns.
 * This is the preferred method as it uses the exact same display values as Wireshark.
 * 
 * @param detailsMap - The mapping from backend (idx -> frame number)
 * @param packetColumns - Map of frame.number -> PacketColumns from tshark
 * @param annotations - Optional annotations for IP→NE naming (aligns with diagram)
 */
export function deriveFlowDetailsFromTsharkColumns(
  detailsMap: FlowDetailMapping[],
  packetColumns: Record<string, PacketColumns>,
  annotations?: FlowAnnotationsV1 | null
): RichFlowDetail[] {
  // Build IP maps for annotations-based naming
  const ipMaps = annotations ? buildIPMaps(annotations) : null
  
  return detailsMap.map((mapping, arrayIdx) => {
    const cols = packetColumns[mapping.originNumber]
    
    if (!cols) {
      return {
        idx: mapping.idx,
        frame: mapping.frame,
        originNumber: mapping.originNumber,
        title: `Frame ${mapping.originNumber}`,
        detail_lines: [],
        fields: {},
      }
    }
    
    // Use tshark-extracted Protocol directly
    const protocol = cols.protocol
    
    // Get from/to using annotations if available, otherwise use tshark source/destination
    let from: string, to: string
    
    if (ipMaps && ipMaps.ipToNE.size > 0) {
      // Use annotations: simple display without sequence numbers for detail list
      const srcRole = ipMaps.ipToNE.get(cols.source) || 'Unknown'
      const dstRole = ipMaps.ipToNE.get(cols.destination) || 'Unknown'
      from = srcRole === 'Unknown' ? cols.source : `${srcRole}(${cols.source})`
      to = dstRole === 'Unknown' ? cols.destination : `${dstRole}(${cols.destination})`
    } else {
      // No annotations: just use raw source/destination from tshark
      from = cols.source
      to = cols.destination
    }
    
    // Title: use Protocol + cleaned Info (matches Mermaid arrow label)
    const title = `${cols.protocol} ${cols.info_clean}`
    
    // Detail lines: comprehensive tshark column info
    const detail_lines: string[] = [
      `Frame: ${cols.frame_number}`,
      `Time: ${cols.time_relative}s`,
      `${cols.source} → ${cols.destination}`,
      `Length: ${cols.length} bytes`,
      `Protocol: ${cols.protocol}`,
      `Info: ${cols.info_clean}`,
    ]
    
    // Fields for expandable JSON view
    const fields: Record<string, unknown> = {
      frame: {
        number: cols.frame_number,
        time: cols.time_relative,
        length: cols.length,
      },
      layers: {
        src_ip: cols.source,
        dst_ip: cols.destination,
      },
      protocol: cols.protocol,
      info: cols.info,
      info_clean: cols.info_clean,
    }
    
    return {
      idx: mapping.idx,
      frame: arrayIdx + 1, // 1-based array index
      originNumber: mapping.originNumber,
      from,
      to,
      protocol,
      title,
      detail_lines,
      fields,
    }
  })
}
