export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ThreatCategory = 
  | 'ip_leak' 
  | 'email_exposure' 
  | 'credential_leak' 
  | 'api_key_exposure'
  | 'sensitive_data'
  | 'malicious_content'
  | 'phishing_indicator';

export interface ThreatFinding {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  title: string;
  description: string;
  evidence: string;
  timestamp: string;
  remediation: string;
  confidenceScore?: number; // 0.0 to 1.0
  falsePositive?: boolean;
}

export interface MonitoredUrl {
  id: string;
  url: string;
  type: 'surface' | 'darkweb';
  status: 'active' | 'paused' | 'error';
  lastScan: string;
  nextScan: string;
  riskScore: number;
  threatCount: number;
  findings: ThreatFinding[];
  addedAt: string;
  scanInterval?: number; // seconds between scans
}

export interface ThreatAlert {
  id: string;
  urlId: string;
  url: string;
  severity: ThreatSeverity;
  message: string;
  timestamp: string;
  acknowledged: boolean;
}

// Database response types
export interface DbMonitoredUrl {
  id: number;
  url: string;
  type: 'surface' | 'darkweb';
  status: 'active' | 'paused' | 'error';
  riskScore: number;
  threatCount: number;
  scanInterval: number;
  lastScan: number | null;
  nextScan: number | null;
  addedAt: number;
  updatedAt: number | null;
}

export interface DbThreatFinding {
  id: number;
  urlId: number;
  category: string;
  severity: ThreatSeverity;
  title: string;
  description: string | null;
  evidence: string | null;
  remediation: string | null;
  confidenceScore: number;
  falsePositive: boolean;
  createdAt: number;
}

export interface DbScanHistory {
  id: number;
  urlId: number;
  scanTimestamp: number;
  riskScore: number | null;
  threatsFound: number | null;
  scanDuration: number | null;
  status: string | null;
}

export interface ScanHistoryStats {
  totalScans: number;
  averageRiskScore: number;
  totalThreatsFound: number;
  averageScanDuration: number;
  successRate: number;
  recentScans: DbScanHistory[];
}