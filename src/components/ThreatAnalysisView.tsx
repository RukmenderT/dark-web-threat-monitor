"use client";

import { MonitoredUrl, ThreatCategory } from '@/types/threat';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { 
  X, 
  RefreshCw,
  AlertTriangle,
  Shield,
  Mail,
  Key,
  Eye,
  FileText,
  Bug,
  Globe,
  Loader2
} from 'lucide-react';
import { getSeverityColor, getSeverityBadgeVariant } from '@/lib/threatAnalysis';

interface ThreatAnalysisViewProps {
  url: MonitoredUrl;
  onClose: () => void;
  onRescan: () => void;
  isRescanning?: boolean;
}

const categoryIcons: Record<ThreatCategory, React.ElementType> = {
  ip_leak: Globe,
  email_exposure: Mail,
  credential_leak: Key,
  api_key_exposure: Key,
  sensitive_data: FileText,
  malicious_content: Bug,
  phishing_indicator: AlertTriangle,
};

const categoryDescriptions: Record<ThreatCategory, string> = {
  ip_leak: 'IP addresses exposed in public content',
  email_exposure: 'Email addresses accessible to unauthorized parties',
  credential_leak: 'Authentication credentials found in accessible locations',
  api_key_exposure: 'API keys or access tokens exposed',
  sensitive_data: 'Sensitive or confidential information patterns detected',
  malicious_content: 'Potentially malicious patterns or behavior detected',
  phishing_indicator: 'Indicators of phishing or social engineering',
};

export function ThreatAnalysisView({ url, onClose, onRescan, isRescanning = false }: ThreatAnalysisViewProps) {
  const categorizedFindings = url.findings.reduce((acc, finding) => {
    if (!acc[finding.category]) {
      acc[finding.category] = [];
    }
    acc[finding.category].push(finding);
    return acc;
  }, {} as Record<ThreatCategory, typeof url.findings>);

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500';
    if (score >= 50) return 'text-orange-500';
    if (score >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const handleClose = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onClose();
  };

  const handleRescan = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onRescan();
  };

  return (
    <div 
      className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={handleClose}
    >
      <div 
        className="w-full max-w-6xl max-h-[95vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="border-b border-gray-800 sticky top-0 bg-gray-900 z-10">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-2">
                  <Shield className="h-6 w-6 text-purple-400 flex-shrink-0" />
                  <CardTitle className="text-xl text-white">Threat Analysis Report</CardTitle>
                </div>
                <CardDescription className="flex items-center gap-2 flex-wrap mt-2">
                  <code className="text-sm font-mono text-purple-300 break-all">
                    {url.url}
                  </code>
                  <Badge variant={url.type === 'darkweb' ? 'destructive' : 'secondary'} className="flex-shrink-0">
                    {url.type === 'darkweb' ? 'Dark Web' : 'Surface Web'}
                  </Badge>
                </CardDescription>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleRescan}
                  disabled={isRescanning}
                  className="hover:bg-gray-800 border-gray-700"
                  title="Rescan URL"
                >
                  {isRescanning ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <RefreshCw className="h-4 w-4 mr-1" />
                      Rescan
                    </>
                  )}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleClose}
                  className="hover:bg-gray-800 border-gray-700"
                  title="Close"
                >
                  <X className="h-4 w-4 mr-1" />
                  Close
                </Button>
              </div>
            </div>
          </CardHeader>

          <CardContent className="p-6 space-y-6">
            {/* Summary Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <Card className="bg-gray-800/50 border-gray-700">
                <CardContent className="pt-6">
                  <div className="text-center">
                    <div className={`text-4xl font-bold mb-2 ${getRiskColor(url.riskScore)}`}>
                      {url.riskScore}
                    </div>
                    <p className="text-sm text-gray-300">Risk Score</p>
                  </div>
                </CardContent>
              </Card>
              <Card className="bg-gray-800/50 border-gray-700">
                <CardContent className="pt-6">
                  <div className="text-center">
                    <div className="text-4xl font-bold mb-2 text-orange-400">
                      {url.threatCount}
                    </div>
                    <p className="text-sm text-gray-300">Total Threats</p>
                  </div>
                </CardContent>
              </Card>
              <Card className="bg-gray-800/50 border-gray-700">
                <CardContent className="pt-6">
                  <div className="text-center">
                    <div className="text-4xl font-bold mb-2 text-purple-400">
                      {Object.keys(categorizedFindings).length}
                    </div>
                    <p className="text-sm text-gray-300">Categories</p>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Separator className="bg-gray-800" />

            {/* Threats by Category */}
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-white">
                <AlertTriangle className="h-5 w-5 text-orange-400" />
                Detected Threats by Category
              </h3>
              
              {url.findings.length === 0 ? (
                <Card className="bg-gray-800/30 border-gray-700 border-dashed">
                  <CardContent className="py-12 text-center text-gray-400">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-50 text-green-500" />
                    <p>No threats detected. This URL appears secure.</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-6">
                  {Object.entries(categorizedFindings).map(([category, findings]) => {
                    const Icon = categoryIcons[category as ThreatCategory];
                    return (
                      <Card key={category} className="bg-gray-800/50 border-gray-700">
                        <CardHeader>
                          <div className="flex items-center justify-between gap-4 flex-wrap">
                            <CardTitle className="text-base flex items-center gap-2 text-white">
                              <Icon className="h-5 w-5 text-purple-400" />
                              {category.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                            </CardTitle>
                            <Badge variant="secondary">
                              {findings.length} finding{findings.length > 1 ? 's' : ''}
                            </Badge>
                          </div>
                          <CardDescription className="break-words text-gray-300">
                            {categoryDescriptions[category as ThreatCategory]}
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          {findings.map((finding) => (
                            <div 
                              key={finding.id}
                              className="bg-gray-900/50 border border-gray-700 rounded-lg p-4 space-y-3"
                            >
                              <div className="flex items-start justify-between gap-4">
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                                    <Badge variant={getSeverityBadgeVariant(finding.severity)}>
                                      {finding.severity.toUpperCase()}
                                    </Badge>
                                    <span className="text-xs text-gray-400">
                                      {new Date(finding.timestamp).toLocaleString()}
                                    </span>
                                  </div>
                                  <h4 className="font-semibold text-gray-100 mb-1 break-words">
                                    {finding.title}
                                  </h4>
                                  <p className="text-sm text-gray-300 break-words whitespace-pre-wrap">
                                    {finding.description}
                                  </p>
                                </div>
                              </div>

                              <div className="space-y-3">
                                <div>
                                  <p className="text-xs font-medium text-gray-400 mb-1">
                                    Evidence:
                                  </p>
                                  <div className="bg-gray-950 rounded border border-gray-800 p-3 max-h-40 overflow-y-auto">
                                    <code className="text-xs text-gray-200 break-all whitespace-pre-wrap block">
                                      {finding.evidence}
                                    </code>
                                  </div>
                                </div>

                                {finding.remediation && (
                                  <div>
                                    <p className="text-xs font-medium text-gray-400 mb-1">
                                      Remediation:
                                    </p>
                                    <div className="bg-blue-900/20 border border-blue-800/50 rounded p-3 max-h-60 overflow-y-auto">
                                      <p className="text-xs text-blue-100 break-words whitespace-pre-wrap">
                                        {finding.remediation}
                                      </p>
                                    </div>
                                  </div>
                                )}

                                {finding.confidenceScore !== undefined && (
                                  <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-400">Confidence Score:</span>
                                    <span className="font-semibold text-gray-200">
                                      {(finding.confidenceScore * 100).toFixed(0)}%
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Scan Information */}
            <Separator className="bg-gray-800" />
            
            <div className="bg-gray-800/30 rounded-lg p-4 border border-gray-700">
              <h4 className="text-sm font-semibold mb-3 text-gray-300">Scan Information</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-400">Last Scanned:</span>
                  <p className="text-gray-200 font-medium break-words">
                    {new Date(url.lastScan).toLocaleString()}
                  </p>
                </div>
                <div>
                  <span className="text-gray-400">Next Scan:</span>
                  <p className="text-gray-200 font-medium break-words">
                    {new Date(url.nextScan).toLocaleString()}
                  </p>
                </div>
                <div>
                  <span className="text-gray-400">Status:</span>
                  <p className="text-gray-200 font-medium capitalize">{url.status}</p>
                </div>
                <div>
                  <span className="text-gray-400">Added:</span>
                  <p className="text-gray-200 font-medium">
                    {new Date(url.addedAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}