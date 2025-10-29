"use client";

import { useState, useEffect } from 'react';
import { MonitoredUrl, ThreatAlert } from '@/types/threat';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  AlertTriangle, 
  Shield, 
  TrendingUp, 
  Activity,
  Clock,
  CheckCircle2,
  XCircle,
  Bell
} from 'lucide-react';
import { getSeverityColor } from '@/lib/threatAnalysis';

interface MonitoringDashboardProps {
  monitoredUrls: MonitoredUrl[];
  alerts: ThreatAlert[];
  onAcknowledgeAlert: (alertId: string) => void;
}

export function MonitoringDashboard({ 
  monitoredUrls, 
  alerts,
  onAcknowledgeAlert 
}: MonitoringDashboardProps) {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const totalThreats = monitoredUrls.reduce((acc, url) => acc + url.threatCount, 0);
  const averageRiskScore = monitoredUrls.length > 0
    ? Math.round(monitoredUrls.reduce((acc, url) => acc + url.riskScore, 0) / monitoredUrls.length)
    : 0;
  const activeMonitoring = monitoredUrls.filter(u => u.status === 'active').length;
  const criticalThreats = monitoredUrls.reduce((acc, url) => 
    acc + url.findings.filter(f => f.severity === 'critical').length, 0
  );

  const recentAlerts = alerts.slice(0, 10);
  const unacknowledgedCount = alerts.filter(a => !a.acknowledged).length;

  // Generate timeline data
  const timeline = [...alerts]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 20);

  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-purple-900/50 to-purple-800/30 border-purple-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Total Threats</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="text-3xl font-bold text-white">{totalThreats}</div>
              <AlertTriangle className="h-8 w-8 text-purple-300" />
            </div>
            <p className="text-xs text-purple-200 mt-2">Across all monitored URLs</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-900/50 to-orange-800/30 border-orange-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Average Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="text-3xl font-bold text-white">{averageRiskScore}/100</div>
              <TrendingUp className="h-8 w-8 text-orange-300" />
            </div>
            <p className="text-xs text-orange-200 mt-2">Overall threat level</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-900/50 to-green-800/30 border-green-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Active Monitoring</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="text-3xl font-bold text-white">{activeMonitoring}</div>
              <Activity className="h-8 w-8 text-green-300" />
            </div>
            <p className="text-xs text-green-200 mt-2">URLs being tracked</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-red-900/50 to-red-800/30 border-red-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Critical Threats</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="text-3xl font-bold text-white">{criticalThreats}</div>
              <Shield className="h-8 w-8 text-red-300" />
            </div>
            <p className="text-xs text-red-200 mt-2">Require immediate action</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Real-time Alerts */}
        <Card className="bg-gray-900/50 border-gray-800">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="h-5 w-5 text-red-400" />
                  Active Alerts
                </CardTitle>
                <CardDescription>
                  {unacknowledgedCount} unacknowledged alert(s)
                </CardDescription>
              </div>
              <Badge variant="destructive" className="text-lg px-3 py-1">
                {unacknowledgedCount}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px] pr-4">
              {recentAlerts.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <CheckCircle2 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No active alerts. System is secure.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {recentAlerts.map((alert) => (
                    <Alert 
                      key={alert.id}
                      className={`${
                        alert.acknowledged 
                          ? 'bg-gray-800/30 border-gray-700' 
                          : 'bg-red-900/20 border-red-800'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge 
                              variant={alert.severity === 'critical' ? 'destructive' : 'default'}
                              className="text-xs"
                            >
                              {alert.severity.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-gray-500">
                              {new Date(alert.timestamp).toLocaleString()}
                            </span>
                          </div>
                          <AlertDescription className="text-sm">
                            <p className="font-medium text-gray-200 mb-1">{alert.message}</p>
                            <code className="text-xs text-purple-300 break-all">
                              {alert.url}
                            </code>
                          </AlertDescription>
                        </div>
                        {!alert.acknowledged && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => onAcknowledgeAlert(alert.id)}
                            className="hover:bg-gray-800"
                          >
                            <CheckCircle2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </Alert>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Threat Timeline */}
        <Card className="bg-gray-900/50 border-gray-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-blue-400" />
              Threat Timeline
            </CardTitle>
            <CardDescription>
              Recent threat detection history
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px] pr-4">
              {timeline.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No threat history yet.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {timeline.map((event, index) => (
                    <div key={event.id} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className={`w-3 h-3 rounded-full ${
                          event.severity === 'critical' ? 'bg-red-500' :
                          event.severity === 'high' ? 'bg-orange-500' :
                          'bg-yellow-500'
                        }`} />
                        {index < timeline.length - 1 && (
                          <div className="w-0.5 h-full bg-gray-800 mt-2" />
                        )}
                      </div>
                      <div className="flex-1 pb-4">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-sm font-medium ${getSeverityColor(event.severity)}`}>
                            {event.severity.toUpperCase()}
                          </span>
                          <span className="text-xs text-gray-500">
                            {new Date(event.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-300 mb-1">{event.message}</p>
                        <code className="text-xs text-gray-500 break-all">
                          {event.url}
                        </code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {/* Severity Distribution */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <CardTitle>Threat Severity Distribution</CardTitle>
          <CardDescription>Breakdown of threats by severity level</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-4">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => {
              const count = monitoredUrls.reduce((acc, url) => 
                acc + url.findings.filter(f => f.severity === severity).length, 0
              );
              return (
                <div key={severity} className="text-center">
                  <div className={`text-3xl font-bold mb-2 ${getSeverityColor(severity)}`}>
                    {count}
                  </div>
                  <Badge variant="outline" className="capitalize">
                    {severity}
                  </Badge>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Live Status */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardContent className="py-4">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              <span className="text-gray-400">System Status: Online</span>
            </div>
            <div className="text-gray-500">
              Last updated: {currentTime.toLocaleTimeString()}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
