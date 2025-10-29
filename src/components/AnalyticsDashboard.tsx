"use client";

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';
import { 
  TrendingUp, TrendingDown, Activity, Shield, Download,
  BarChart3, PieChart as PieChartIcon, LineChart as LineChartIcon,
  FileText, AlertTriangle
} from 'lucide-react';
import { DbScanHistory, DbThreatFinding, ScanHistoryStats } from '@/types/threat';
import { calculateThreatStatistics, exportThreatDataAsCSV, exportThreatDataAsJSON } from '@/lib/threatAnalysis';

interface AnalyticsDashboardProps {
  findings: DbThreatFinding[];
  scanHistory: DbScanHistory[];
  stats: ScanHistoryStats;
}

const COLORS = {
  critical: '#ef4444',
  high: '#f97316', 
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const CATEGORY_COLORS = ['#8b5cf6', '#ec4899', '#06b6d4', '#10b981', '#f59e0b', '#6366f1', '#ef4444'];

export function AnalyticsDashboard({ findings, scanHistory, stats }: AnalyticsDashboardProps) {
  const [activeTab, setActiveTab] = useState('overview');

  // Convert findings to appropriate format for statistics
  const threatFindings = findings.map(f => ({
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
  }));

  const statistics = calculateThreatStatistics(threatFindings);

  // Prepare severity distribution data for pie chart
  const severityData = Object.entries(statistics.severityDistribution).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    percentage: statistics.totalFindings > 0 ? ((value / statistics.totalFindings) * 100).toFixed(1) : '0.0',
  }));

  // Prepare category distribution data for bar chart
  const categoryData = Object.entries(statistics.categoryDistribution).map(([name, value]) => ({
    name: name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
    count: value,
  }));

  // Prepare time series data from scan history
  const timeSeriesData = scanHistory
    .slice()
    .sort((a, b) => a.scanTimestamp - b.scanTimestamp)
    .slice(-20) // Last 20 scans
    .map(scan => ({
      time: new Date(scan.scanTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      riskScore: scan.riskScore || 0,
      threats: scan.threatsFound || 0,
      timestamp: scan.scanTimestamp,
    }));

  // Prepare confidence distribution data
  const confidenceRanges = {
    'Very High (90-100%)': 0,
    'High (80-90%)': 0,
    'Medium (70-80%)': 0,
    'Low (60-70%)': 0,
    'Very Low (<60%)': 0,
  };

  findings.forEach(f => {
    const conf = f.confidenceScore * 100;
    if (conf >= 90) confidenceRanges['Very High (90-100%)']++;
    else if (conf >= 80) confidenceRanges['High (80-90%)']++;
    else if (conf >= 70) confidenceRanges['Medium (70-80%)']++;
    else if (conf >= 60) confidenceRanges['Low (60-70%)']++;
    else confidenceRanges['Very Low (<60%)']++;
  });

  const confidenceData = Object.entries(confidenceRanges).map(([name, value]) => ({
    name,
    value,
  }));

  // Threat severity radar data
  const radarData = [
    { threat: 'Critical', score: statistics.severityDistribution.critical * 20 },
    { threat: 'High', score: statistics.severityDistribution.high * 15 },
    { threat: 'Medium', score: statistics.severityDistribution.medium * 10 },
    { threat: 'Low', score: statistics.severityDistribution.low * 5 },
    { threat: 'Info', score: statistics.severityDistribution.info * 2 },
  ];

  const handleExportCSV = () => {
    const csv = exportThreatDataAsCSV(threatFindings);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-analysis-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportJSON = () => {
    const json = exportThreatDataAsJSON(threatFindings, statistics);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-analysis-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const riskTrend = timeSeriesData.length >= 2 
    ? timeSeriesData[timeSeriesData.length - 1].riskScore - timeSeriesData[0].riskScore
    : 0;

  return (
    <div className="space-y-6">
      {/* Header with Export Options */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
            Advanced Threat Analytics
          </h2>
          <p className="text-gray-400 text-sm mt-1">Research-grade data visualization and statistical analysis</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportCSV}
            className="gap-2 border-gray-700 hover:bg-gray-800"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportJSON}
            className="gap-2 border-gray-700 hover:bg-gray-800"
          >
            <FileText className="h-4 w-4" />
            Export JSON
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="bg-gradient-to-br from-purple-900/50 to-purple-800/30 border-purple-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Total Findings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">{statistics.totalFindings}</div>
            <p className="text-xs text-purple-200 mt-1">Detected threats</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-blue-900/50 to-blue-800/30 border-blue-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Avg Confidence</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">
              {(statistics.averageConfidence * 100).toFixed(1)}%
            </div>
            <p className="text-xs text-blue-200 mt-1">Detection accuracy</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-900/50 to-orange-800/30 border-orange-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Criticality Index</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">{statistics.criticalityIndex}/100</div>
            <p className="text-xs text-orange-200 mt-1">Threat severity score</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-900/50 to-green-800/30 border-green-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">False Positive Rate</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">
              {(statistics.falsePositiveRate * 100).toFixed(1)}%
            </div>
            <p className="text-xs text-green-200 mt-1">Quality metric</p>
          </CardContent>
        </Card>

        <Card className={`bg-gradient-to-br ${riskTrend > 0 ? 'from-red-900/50 to-red-800/30 border-red-700/50' : 'from-green-900/50 to-green-800/30 border-green-700/50'}`}>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300">Risk Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-white">
                {riskTrend > 0 ? '+' : ''}{riskTrend.toFixed(0)}
              </div>
              {riskTrend > 0 ? (
                <TrendingUp className="h-6 w-6 text-red-400" />
              ) : (
                <TrendingDown className="h-6 w-6 text-green-400" />
              )}
            </div>
            <p className="text-xs text-gray-200 mt-1">{riskTrend > 0 ? 'Increasing' : 'Improving'}</p>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="bg-gray-900/50 border border-gray-800">
          <TabsTrigger value="overview" className="gap-2">
            <BarChart3 className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="trends" className="gap-2">
            <LineChartIcon className="h-4 w-4" />
            Trends
          </TabsTrigger>
          <TabsTrigger value="distribution" className="gap-2">
            <PieChartIcon className="h-4 w-4" />
            Distribution
          </TabsTrigger>
          <TabsTrigger value="detailed" className="gap-2">
            <AlertTriangle className="h-4 w-4" />
            Detailed
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Risk Score Timeline */}
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle>Risk Score Timeline</CardTitle>
                <CardDescription>Historical risk score progression</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={timeSeriesData}>
                    <defs>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="time" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                    <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#f3f4f6'
                      }} 
                    />
                    <Area 
                      type="monotone" 
                      dataKey="riskScore" 
                      stroke="#8b5cf6" 
                      fillOpacity={1} 
                      fill="url(#colorRisk)" 
                      name="Risk Score"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Severity Distribution Pie */}
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle>Severity Distribution</CardTitle>
                <CardDescription>Breakdown by threat severity levels</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percentage }) => `${name}: ${percentage}%`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[entry.name.toLowerCase() as keyof typeof COLORS]} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#f3f4f6'
                      }} 
                    />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Category Distribution Bar Chart */}
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle>Threat Category Distribution</CardTitle>
              <CardDescription>Number of threats by category type</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={350}>
                <BarChart data={categoryData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis 
                    dataKey="name" 
                    stroke="#9ca3af" 
                    style={{ fontSize: '12px' }}
                    angle={-15}
                    textAnchor="end"
                    height={80}
                  />
                  <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#f3f4f6'
                    }} 
                  />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[8, 8, 0, 0]}>
                    {categoryData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="trends" className="space-y-6">
          {/* Threat Accumulation Over Time */}
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle>Threat Detection Timeline</CardTitle>
              <CardDescription>Cumulative threats detected over scanning period</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <LineChart data={timeSeriesData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                  <YAxis yAxisId="left" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                  <YAxis yAxisId="right" orientation="right" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#f3f4f6'
                    }} 
                  />
                  <Legend />
                  <Line 
                    yAxisId="left"
                    type="monotone" 
                    dataKey="riskScore" 
                    stroke="#8b5cf6" 
                    strokeWidth={3}
                    dot={{ fill: '#8b5cf6', r: 4 }}
                    name="Risk Score"
                  />
                  <Line 
                    yAxisId="right"
                    type="monotone" 
                    dataKey="threats" 
                    stroke="#ec4899" 
                    strokeWidth={3}
                    dot={{ fill: '#ec4899', r: 4 }}
                    name="Threats Found"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Scan Performance Metrics */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle className="text-base">Total Scans</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-4xl font-bold text-purple-400">{stats.totalScans}</div>
                <p className="text-sm text-gray-400 mt-2">Completed analyses</p>
              </CardContent>
            </Card>

            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle className="text-base">Avg Scan Duration</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-4xl font-bold text-blue-400">
                  {(stats.averageScanDuration / 1000).toFixed(1)}s
                </div>
                <p className="text-sm text-gray-400 mt-2">Per analysis</p>
              </CardContent>
            </Card>

            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle className="text-base">Success Rate</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-4xl font-bold text-green-400">{stats.successRate.toFixed(1)}%</div>
                <p className="text-sm text-gray-400 mt-2">Successful scans</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="distribution" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Confidence Score Distribution */}
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle>Confidence Score Distribution</CardTitle>
                <CardDescription>Detection confidence levels across findings</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={350}>
                  <BarChart data={confidenceData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis type="number" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                    <YAxis type="category" dataKey="name" stroke="#9ca3af" style={{ fontSize: '11px' }} width={120} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#f3f4f6'
                      }} 
                    />
                    <Bar dataKey="value" fill="#06b6d4" radius={[0, 8, 8, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Threat Severity Radar */}
            <Card className="bg-gray-900/50 border-gray-800">
              <CardHeader>
                <CardTitle>Threat Severity Radar</CardTitle>
                <CardDescription>Multi-dimensional threat assessment</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={350}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="#374151" />
                    <PolarAngleAxis dataKey="threat" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                    <PolarRadiusAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
                    <Radar 
                      name="Threat Level" 
                      dataKey="score" 
                      stroke="#8b5cf6" 
                      fill="#8b5cf6" 
                      fillOpacity={0.6} 
                    />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#f3f4f6'
                      }} 
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="detailed" className="space-y-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle>Statistical Summary</CardTitle>
              <CardDescription>Comprehensive threat intelligence metrics for research analysis</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-gray-400">SEVERITY BREAKDOWN</h4>
                  <div className="space-y-2">
                    {Object.entries(statistics.severityDistribution).map(([severity, count]) => (
                      <div key={severity} className="flex items-center justify-between">
                        <Badge 
                          variant={severity === 'critical' || severity === 'high' ? 'destructive' : 'secondary'}
                          className="capitalize"
                        >
                          {severity}
                        </Badge>
                        <span className="text-lg font-bold text-gray-200">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-gray-400">QUALITY METRICS</h4>
                  <div className="space-y-3">
                    <div>
                      <p className="text-xs text-gray-500">Average Confidence</p>
                      <div className="flex items-center gap-2 mt-1">
                        <div className="flex-1 bg-gray-800 rounded-full h-2">
                          <div 
                            className="bg-green-500 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${statistics.averageConfidence * 100}%` }}
                          />
                        </div>
                        <span className="text-sm font-bold text-gray-200">
                          {(statistics.averageConfidence * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>

                    <div>
                      <p className="text-xs text-gray-500">False Positive Rate</p>
                      <div className="flex items-center gap-2 mt-1">
                        <div className="flex-1 bg-gray-800 rounded-full h-2">
                          <div 
                            className="bg-yellow-500 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${statistics.falsePositiveRate * 100}%` }}
                          />
                        </div>
                        <span className="text-sm font-bold text-gray-200">
                          {(statistics.falsePositiveRate * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>

                    <div>
                      <p className="text-xs text-gray-500">Criticality Index</p>
                      <div className="flex items-center gap-2 mt-1">
                        <div className="flex-1 bg-gray-800 rounded-full h-2">
                          <div 
                            className="bg-red-500 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${statistics.criticalityIndex}%` }}
                          />
                        </div>
                        <span className="text-sm font-bold text-gray-200">
                          {statistics.criticalityIndex}/100
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-gray-400">SCAN PERFORMANCE</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between py-2 border-b border-gray-800">
                      <span className="text-sm text-gray-400">Total Scans</span>
                      <span className="text-lg font-bold text-gray-200">{stats.totalScans}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-gray-800">
                      <span className="text-sm text-gray-400">Avg Risk Score</span>
                      <span className="text-lg font-bold text-gray-200">{stats.averageRiskScore.toFixed(1)}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-gray-800">
                      <span className="text-sm text-gray-400">Total Threats</span>
                      <span className="text-lg font-bold text-gray-200">{stats.totalThreatsFound}</span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                      <span className="text-sm text-gray-400">Avg Duration</span>
                      <span className="text-lg font-bold text-gray-200">{(stats.averageScanDuration / 1000).toFixed(2)}s</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-blue-900/20 border border-blue-800/50 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-blue-300 mb-2 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Research Notes
                </h4>
                <p className="text-sm text-blue-200/80">
                  This dashboard provides research-grade threat intelligence metrics suitable for academic publication. 
                  All data can be exported in CSV or JSON format for further statistical analysis using tools like R, Python, or SPSS.
                  Confidence scores are calculated using pattern matching algorithms with validation against known threat databases.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
