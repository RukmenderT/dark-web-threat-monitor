"use client";

import { useState, useEffect, useCallback } from 'react';
import { MonitoredUrl, ThreatAlert, DbMonitoredUrl, DbThreatFinding, DbScanHistory, ScanHistoryStats } from '@/types/threat';
import { analyzeUrlForThreats, calculateRiskScore } from '@/lib/threatAnalysis';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { 
  Shield, 
  Plus, 
  AlertTriangle, 
  Eye, 
  Pause, 
  Play, 
  Trash2,
  Globe,
  Activity,
  Clock,
  Bell,
  Search,
  Settings,
  BarChart3,
  RefreshCw,
  Loader2
} from 'lucide-react';
import { MonitoringDashboard } from './MonitoringDashboard';
import { ThreatAnalysisView } from './ThreatAnalysisView';
import { AnalyticsDashboard } from './AnalyticsDashboard';
import { toast } from 'sonner';

const SCAN_INTERVALS = [
  { label: '30 seconds', value: 30 },
  { label: '1 minute', value: 60 },
  { label: '5 minutes', value: 300 },
  { label: '15 minutes', value: 900 },
  { label: '30 minutes', value: 1800 },
  { label: '1 hour', value: 3600 },
];

export function ThreatMonitor() {
  const [monitoredUrls, setMonitoredUrls] = useState<MonitoredUrl[]>([]);
  const [newUrl, setNewUrl] = useState('');
  const [urlType, setUrlType] = useState<'surface' | 'darkweb'>('surface');
  const [scanInterval, setScanInterval] = useState(300);
  const [isAdding, setIsAdding] = useState(false);
  const [selectedUrl, setSelectedUrl] = useState<MonitoredUrl | null>(null);
  const [isRescanning, setIsRescanning] = useState(false);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [activeTab, setActiveTab] = useState('monitor');
  const [isLoading, setIsLoading] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  
  // Analytics data
  const [allFindings, setAllFindings] = useState<DbThreatFinding[]>([]);
  const [scanHistory, setScanHistory] = useState<DbScanHistory[]>([]);
  const [scanStats, setScanStats] = useState<ScanHistoryStats>({
    totalScans: 0,
    averageRiskScore: 0,
    totalThreatsFound: 0,
    averageScanDuration: 0,
    successRate: 0,
    recentScans: [],
  });

  // Load monitored URLs from database on mount
  const loadMonitoredUrls = useCallback(async () => {
    try {
      const response = await fetch('/api/monitored-urls');
      if (!response.ok) throw new Error('Failed to load URLs');
      
      const dbUrls: DbMonitoredUrl[] = await response.json();
      
      // Convert database format to component format
      const urls: MonitoredUrl[] = await Promise.all(
        dbUrls.map(async (dbUrl) => {
          // Fetch findings for this URL
          const findingsRes = await fetch(`/api/threat-findings?url_id=${dbUrl.id}`);
          const findings: DbThreatFinding[] = await findingsRes.json();
          
          return {
            id: dbUrl.id.toString(),
            url: dbUrl.url,
            type: dbUrl.type,
            status: dbUrl.status,
            lastScan: dbUrl.lastScan ? new Date(dbUrl.lastScan).toISOString() : new Date().toISOString(),
            nextScan: dbUrl.nextScan ? new Date(dbUrl.nextScan).toISOString() : new Date().toISOString(),
            riskScore: dbUrl.riskScore,
            threatCount: dbUrl.threatCount,
            scanInterval: dbUrl.scanInterval,
            findings: findings.map(f => ({
              id: f.id.toString(),
              category: f.category as any,
              severity: f.severity,
              title: f.title,
              description: f.description || '',
              evidence: f.evidence || '',
              timestamp: new Date(f.createdAt).toISOString(),
              remediation: f.remediation || '',
              confidenceScore: f.confidenceScore,
              falsePositive: f.falsePositive,
            })),
            addedAt: new Date(dbUrl.addedAt).toISOString(),
          };
        })
      );
      
      setMonitoredUrls(urls);
      
      // Only update selected URL if one is currently open AND it still exists
      setSelectedUrl(prev => {
        if (!prev) return null;
        const updatedUrl = urls.find(u => u.id === prev.id);
        return updatedUrl || null;
      });
    } catch (error) {
      console.error('Error loading URLs:', error);
      toast.error('Failed to load monitored URLs');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Load analytics data
  const loadAnalytics = useCallback(async () => {
    try {
      const [findingsRes, historyRes, statsRes] = await Promise.all([
        fetch('/api/threat-findings'),
        fetch('/api/scan-history'),
        fetch('/api/scan-history/stats'),
      ]);

      if (findingsRes.ok) {
        const findings = await findingsRes.json();
        setAllFindings(findings);
      }

      if (historyRes.ok) {
        const history = await historyRes.json();
        setScanHistory(history);
      }

      if (statsRes.ok) {
        const stats = await statsRes.json();
        setScanStats(stats);
      }
    } catch (error) {
      console.error('Error loading analytics:', error);
    }
  }, []);

  useEffect(() => {
    loadMonitoredUrls();
    loadAnalytics();
  }, [loadMonitoredUrls, loadAnalytics]);

  // Continuous monitoring with proper dependencies
  useEffect(() => {
    const checkAndScan = async () => {
      const now = Date.now();
      const urlsSnapshot = monitoredUrls;
      
      for (const url of urlsSnapshot) {
        if (url.status === 'active') {
          const nextScanTime = new Date(url.nextScan).getTime();
          if (nextScanTime <= now) {
            // Call rescan without showing toast for auto-scans
            rescanUrl(url.id, false);
          }
        }
      }
    };

    const interval = setInterval(checkAndScan, 10000); // Check every 10 seconds

    return () => clearInterval(interval);
  }, [monitoredUrls]);

  const addUrl = async () => {
    if (!newUrl.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    setIsAdding(true);
    const startTime = Date.now();
    
    try {
      // Perform threat analysis
      const findings = await analyzeUrlForThreats(newUrl, urlType);
      const riskScore = calculateRiskScore(findings);
      const scanDuration = Date.now() - startTime;
      
      const now = Date.now();
      const nextScan = now + (scanInterval * 1000);

      // Create monitored URL in database
      const urlResponse = await fetch('/api/monitored-urls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: newUrl,
          type: urlType,
          status: 'active',
          riskScore,
          threatCount: findings.length,
          scanInterval,
          lastScan: now,
          nextScan,
        }),
      });

      if (!urlResponse.ok) throw new Error('Failed to add URL');
      
      const dbUrl: DbMonitoredUrl = await urlResponse.json();

      // Save findings to database
      await Promise.all(
        findings.map(finding =>
          fetch('/api/threat-findings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              urlId: dbUrl.id,
              category: finding.category,
              severity: finding.severity,
              title: finding.title,
              description: finding.description,
              evidence: finding.evidence,
              remediation: finding.remediation,
              confidenceScore: finding.confidenceScore,
              falsePositive: finding.falsePositive || false,
            }),
          })
        )
      );

      // Save scan history
      await fetch('/api/scan-history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          urlId: dbUrl.id,
          scanTimestamp: now,
          riskScore,
          threatsFound: findings.length,
          scanDuration,
          status: 'success',
        }),
      });

      // Reload data
      await loadMonitoredUrls();
      await loadAnalytics();
      
      // Create alerts for critical/high severity findings
      const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
      if (criticalFindings.length > 0) {
        const newAlerts = criticalFindings.map(finding => ({
          id: `alert_${Date.now()}_${Math.random()}`,
          urlId: dbUrl.id.toString(),
          url: newUrl,
          severity: finding.severity,
          message: finding.title,
          timestamp: new Date().toISOString(),
          acknowledged: false,
        }));
        setAlerts(prev => [...newAlerts, ...prev]);
        toast.warning(`Found ${criticalFindings.length} critical/high severity threat(s)`);
      } else {
        toast.success('URL added successfully');
      }
      
      setNewUrl('');
    } catch (error) {
      console.error('Error adding URL:', error);
      toast.error('Failed to add URL');
    } finally {
      setIsAdding(false);
    }
  };

  const rescanUrl = useCallback(async (urlId: string, showToast: boolean = true) => {
    // Get the latest URL data
    try {
      const urlsResponse = await fetch('/api/monitored-urls');
      
      if (!urlsResponse.ok) {
        if (showToast) toast.error('Failed to fetch URL data');
        return;
      }
      
      const allUrls: DbMonitoredUrl[] = await urlsResponse.json();
      
      // Ensure allUrls is an array
      if (!Array.isArray(allUrls)) {
        console.error('API response is not an array:', allUrls);
        if (showToast) toast.error('Invalid response from server');
        return;
      }
      
      const dbUrl = allUrls.find(u => u.id.toString() === urlId);
      
      if (!dbUrl) {
        if (showToast) toast.error('URL not found');
        return;
      }

      if (showToast) {
        setIsRescanning(true);
        toast.info('Rescanning URL...');
      }

      const startTime = Date.now();

      const findings = await analyzeUrlForThreats(dbUrl.url, dbUrl.type);
      const riskScore = calculateRiskScore(findings);
      const scanDuration = Date.now() - startTime;
      
      const now = Date.now();
      const nextScan = now + ((dbUrl.scanInterval || 300) * 1000);

      // Update URL in database
      await fetch(`/api/monitored-urls?id=${urlId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          riskScore,
          threatCount: findings.length,
          lastScan: now,
          nextScan,
        }),
      });

      // Delete old findings
      const oldFindings = await fetch(`/api/threat-findings?url_id=${urlId}`);
      const oldFindingsData: DbThreatFinding[] = await oldFindings.json();
      await Promise.all(
        oldFindingsData.map(f => 
          fetch(`/api/threat-findings/${f.id}`, { method: 'DELETE' })
        )
      );

      // Save new findings
      await Promise.all(
        findings.map(finding =>
          fetch('/api/threat-findings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              urlId: parseInt(urlId),
              category: finding.category,
              severity: finding.severity,
              title: finding.title,
              description: finding.description,
              evidence: finding.evidence,
              remediation: finding.remediation,
              confidenceScore: finding.confidenceScore,
              falsePositive: finding.falsePositive || false,
            }),
          })
        )
      );

      // Save scan history
      await fetch('/api/scan-history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          urlId: parseInt(urlId),
          scanTimestamp: now,
          riskScore,
          threatsFound: findings.length,
          scanDuration,
          status: 'success',
        }),
      });

      // Reload data
      await loadMonitoredUrls();
      await loadAnalytics();

      // Check for new critical threats
      const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
      
      if (criticalFindings.length > 0 && showToast) {
        toast.warning(`Found ${criticalFindings.length} critical/high severity threat(s)`);
      } else if (showToast) {
        toast.success('Rescan completed successfully');
      }
    } catch (error) {
      console.error('Error rescanning URL:', error);
      if (showToast) {
        toast.error('Failed to rescan URL');
      }
    } finally {
      if (showToast) {
        setIsRescanning(false);
      }
    }
  }, [loadMonitoredUrls, loadAnalytics]);

  const toggleUrlStatus = useCallback(async (urlId: string, event?: React.MouseEvent) => {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    const url = monitoredUrls.find(u => u.id === urlId);
    if (!url) {
      toast.error('URL not found');
      return;
    }

    const newStatus = url.status === 'active' ? 'paused' : 'active';

    try {
      const response = await fetch(`/api/monitored-urls?id=${urlId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });

      if (!response.ok) {
        const errorData = await response.text();
        console.error('Status update failed:', errorData);
        throw new Error('Failed to update status');
      }

      await loadMonitoredUrls();
      toast.success(`Monitoring ${newStatus === 'active' ? 'resumed' : 'paused'}`);
    } catch (error) {
      console.error('Error toggling status:', error);
      toast.error('Failed to update status');
    }
  }, [monitoredUrls, loadMonitoredUrls]);

  const removeUrl = useCallback(async (urlId: string, event?: React.MouseEvent) => {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    try {
      const response = await fetch(`/api/monitored-urls?id=${urlId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.text();
        console.error('Delete failed:', errorData);
        throw new Error('Failed to remove URL');
      }

      await loadMonitoredUrls();
      await loadAnalytics();
      setAlerts(prev => prev.filter(a => a.urlId !== urlId));
      
      // Close modal if this URL was selected
      if (selectedUrl?.id === urlId) {
        setSelectedUrl(null);
      }
      
      toast.success('URL removed successfully');
    } catch (error) {
      console.error('Error removing URL:', error);
      toast.error('Failed to remove URL');
    }
  }, [loadMonitoredUrls, loadAnalytics, selectedUrl]);

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500 font-bold';
    if (score >= 50) return 'text-orange-500 font-bold';
    if (score >= 25) return 'text-yellow-500 font-bold';
    return 'text-green-500 font-bold';
  };

  const unacknowledgedAlerts = alerts.filter(a => !a.acknowledged).length;

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-gray-100 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-12 w-12 animate-spin text-purple-500 mx-auto mb-4" />
          <p className="text-gray-100">Loading threat intelligence data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-gray-100">
      <div className="container mx-auto p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 pb-6">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
              <Shield className="h-8 w-8 text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                Dark Web Threat Intelligence Monitor
              </h1>
              <p className="text-gray-200 text-sm mt-1">Real-time continuous monitoring & advanced analytics</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {unacknowledgedAlerts > 0 && (
              <Badge variant="destructive" className="gap-2 px-4 py-2 text-sm animate-pulse">
                <Bell className="h-4 w-4" />
                {unacknowledgedAlerts} Active Alerts
              </Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSettings(true)}
              className="gap-2 border-gray-700 hover:bg-gray-800"
            >
              <Settings className="h-4 w-4" />
              Settings
            </Button>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-gray-900/50 border border-gray-800">
            <TabsTrigger value="monitor" className="gap-2">
              <Globe className="h-4 w-4" />
              Monitor URLs
            </TabsTrigger>
            <TabsTrigger value="dashboard" className="gap-2">
              <Activity className="h-4 w-4" />
              Live Dashboard
            </TabsTrigger>
            <TabsTrigger value="analytics" className="gap-2">
              <BarChart3 className="h-4 w-4" />
              Analytics
            </TabsTrigger>
          </TabsList>

          <TabsContent value="monitor" className="space-y-6">
            {/* Add URL Form */}
            <Card className="bg-gray-900/50 border-gray-800 shadow-xl">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-xl text-white">
                  <Plus className="h-6 w-6 text-purple-400" />
                  Add URL to Monitor
                </CardTitle>
                <CardDescription className="text-base text-gray-200">
                  Add surface web or dark web URLs for continuous threat monitoring and analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
                  <div className="md:col-span-6 space-y-2">
                    <Label htmlFor="url" className="text-base text-white">URL</Label>
                    <Input
                      id="url"
                      placeholder="https://example.com or http://darkwebsite.onion"
                      value={newUrl}
                      onChange={(e) => setNewUrl(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && !isAdding && addUrl()}
                      className="bg-gray-950/50 border-gray-700 h-11 text-base text-white"
                    />
                  </div>
                  <div className="md:col-span-2 space-y-2">
                    <Label className="text-base text-white">Type</Label>
                    <Select value={urlType} onValueChange={(v: 'surface' | 'darkweb') => setUrlType(v)}>
                      <SelectTrigger className="bg-gray-950/50 border-gray-700 h-11">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="surface">Surface Web</SelectItem>
                        <SelectItem value="darkweb">Dark Web</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="md:col-span-2 space-y-2">
                    <Label className="text-base text-white">Scan Interval</Label>
                    <Select value={scanInterval.toString()} onValueChange={(v) => setScanInterval(parseInt(v))}>
                      <SelectTrigger className="bg-gray-950/50 border-gray-700 h-11">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SCAN_INTERVALS.map(interval => (
                          <SelectItem key={interval.value} value={interval.value.toString()}>
                            {interval.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="md:col-span-2 flex items-end">
                    <Button 
                      onClick={addUrl} 
                      disabled={isAdding || !newUrl.trim()}
                      className="bg-purple-600 hover:bg-purple-700 h-11 w-full font-semibold"
                    >
                      {isAdding ? (
                        <>
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Plus className="h-4 w-4 mr-2" />
                          Add & Scan
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Monitored URLs List */}
            <div className="space-y-4">
              <h2 className="text-2xl font-semibold flex items-center gap-2 text-white">
                <Search className="h-6 w-6 text-purple-400" />
                Monitored URLs ({monitoredUrls.length})
              </h2>
              
              {monitoredUrls.length === 0 ? (
                <Card className="bg-gray-900/30 border-gray-800 border-dashed">
                  <CardContent className="py-16 text-center text-gray-400">
                    <Shield className="h-16 w-16 mx-auto mb-4 opacity-50" />
                    <p className="text-lg">No URLs being monitored yet.</p>
                    <p className="text-sm mt-2">Add a URL above to start threat intelligence monitoring.</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="grid gap-4">
                  {monitoredUrls.map((url) => (
                    <Card 
                      key={url.id} 
                      className="bg-gray-900/50 border-gray-800 hover:border-gray-700 transition-all hover:shadow-xl"
                    >
                      <CardContent className="p-6">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 space-y-4">
                            <div className="flex items-center gap-3 flex-wrap">
                              <Globe className="h-5 w-5 text-gray-300" />
                              <code className="text-base font-mono text-purple-300 break-all flex-1">
                                {url.url}
                              </code>
                              <Badge variant={url.type === 'darkweb' ? 'destructive' : 'secondary'} className="text-sm px-3 py-1">
                                {url.type === 'darkweb' ? '🕵️ Dark Web' : '🌐 Surface'}
                              </Badge>
                              <Badge 
                                variant={url.status === 'active' ? 'default' : 'outline'}
                                className="gap-1 text-sm px-3 py-1"
                              >
                                {url.status === 'active' ? (
                                  <>
                                    <Activity className="h-3 w-3 animate-pulse" />
                                    Active
                                  </>
                                ) : (
                                  <>
                                    <Pause className="h-3 w-3" />
                                    Paused
                                  </>
                                )}
                              </Badge>
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                              <div className="bg-gray-950/50 rounded-lg p-3 border border-gray-800">
                                <p className="text-xs text-gray-400 mb-1">Risk Score</p>
                                <p className={`text-2xl font-bold ${getRiskColor(url.riskScore)}`}>
                                  {url.riskScore}/100
                                </p>
                              </div>
                              <div className="bg-gray-950/50 rounded-lg p-3 border border-gray-800">
                                <p className="text-xs text-gray-400 mb-1">Threats Found</p>
                                <p className="text-2xl font-bold text-orange-400">
                                  {url.threatCount}
                                </p>
                              </div>
                              <div className="bg-gray-950/50 rounded-lg p-3 border border-gray-800">
                                <p className="text-xs text-gray-400 mb-1">Scan Interval</p>
                                <p className="text-lg font-bold text-blue-400">
                                  {SCAN_INTERVALS.find(i => i.value === url.scanInterval)?.label || `${url.scanInterval}s`}
                                </p>
                              </div>
                              <div className="bg-gray-950/50 rounded-lg p-3 border border-gray-800">
                                <p className="text-xs text-gray-400 mb-1">Last Scan</p>
                                <p className="text-sm text-gray-200 font-medium">
                                  {new Date(url.lastScan).toLocaleTimeString()}
                                </p>
                              </div>
                              <div className="bg-gray-950/50 rounded-lg p-3 border border-gray-800">
                                <p className="text-xs text-gray-400 mb-1">Next Scan</p>
                                <p className="text-sm text-gray-200 font-medium flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  {Math.max(0, Math.round((new Date(url.nextScan).getTime() - Date.now()) / 1000))}s
                                </p>
                              </div>
                            </div>
                          </div>

                          <div className="flex flex-col gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedUrl(url);
                              }}
                              className="hover:bg-purple-900/50 border-gray-700"
                            >
                              <Eye className="h-4 w-4 mr-1" />
                              Details
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(e) => {
                                e.stopPropagation();
                                rescanUrl(url.id, true);
                              }}
                              className="hover:bg-blue-900/50 border-gray-700"
                            >
                              <RefreshCw className="h-4 w-4 mr-1" />
                              Rescan
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(e) => toggleUrlStatus(url.id, e)}
                              className="hover:bg-gray-800 border-gray-700"
                            >
                              {url.status === 'active' ? (
                                <>
                                  <Pause className="h-4 w-4 mr-1" />
                                  Pause
                                </>
                              ) : (
                                <>
                                  <Play className="h-4 w-4 mr-1" />
                                  Resume
                                </>
                              )}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(e) => removeUrl(url.id, e)}
                              className="hover:bg-red-900/50 hover:text-red-400 border-gray-700"
                            >
                              <Trash2 className="h-4 w-4 mr-1" />
                              Remove
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="dashboard">
            <MonitoringDashboard 
              monitoredUrls={monitoredUrls}
              alerts={alerts}
              onAcknowledgeAlert={(alertId) => {
                setAlerts(prev => prev.map(a => 
                  a.id === alertId ? { ...a, acknowledged: true } : a
                ));
              }}
            />
          </TabsContent>

          <TabsContent value="analytics">
            <AnalyticsDashboard
              findings={allFindings}
              scanHistory={scanHistory}
              stats={scanStats}
            />
          </TabsContent>
        </Tabs>

        {/* Detailed Analysis Modal */}
        {selectedUrl && (
          <ThreatAnalysisView
            url={selectedUrl}
            onClose={() => setSelectedUrl(null)}
            onRescan={() => rescanUrl(selectedUrl.id, true)}
            isRescanning={isRescanning}
          />
        )}

        {/* Settings Dialog */}
        <Dialog open={showSettings} onOpenChange={setShowSettings}>
          <DialogContent className="bg-gray-900 border-gray-800">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-white">
                <Settings className="h-5 w-5" />
                Monitoring Settings
              </DialogTitle>
              <DialogDescription className="text-gray-300">
                Configure default monitoring preferences
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label className="text-white">Default Scan Interval</Label>
                <Select value={scanInterval.toString()} onValueChange={(v) => setScanInterval(parseInt(v))}>
                  <SelectTrigger className="bg-gray-950/50 border-gray-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCAN_INTERVALS.map(interval => (
                      <SelectItem key={interval.value} value={interval.value.toString()}>
                        {interval.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-gray-400">
                  This will be the default interval for new URLs. You can customize per URL.
                </p>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}