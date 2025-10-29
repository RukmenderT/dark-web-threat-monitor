import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { scanHistory } from '@/db/schema';
import { eq, desc, sql, count, avg, sum } from 'drizzle-orm';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const urlId = searchParams.get('url_id');

    // Base condition for filtering
    const whereCondition = urlId ? eq(scanHistory.urlId, parseInt(urlId)) : undefined;

    // Calculate total scans
    const totalScansResult = await db
      .select({ count: count() })
      .from(scanHistory)
      .where(whereCondition);
    
    const totalScans = totalScansResult[0]?.count || 0;

    // If no scans exist, return zeros and empty arrays
    if (totalScans === 0) {
      return NextResponse.json({
        totalScans: 0,
        averageRiskScore: 0,
        totalThreatsFound: 0,
        averageScanDuration: 0,
        successRate: 0,
        recentScans: []
      }, { status: 200 });
    }

    // Calculate average risk score
    const avgRiskScoreResult = await db
      .select({ avgRiskScore: avg(scanHistory.riskScore) })
      .from(scanHistory)
      .where(whereCondition);
    
    const averageRiskScore = Math.round((Number(avgRiskScoreResult[0]?.avgRiskScore) || 0) * 100) / 100;

    // Calculate total threats found
    const totalThreatsResult = await db
      .select({ totalThreats: sum(scanHistory.threatsFound) })
      .from(scanHistory)
      .where(whereCondition);
    
    const totalThreatsFound = Number(totalThreatsResult[0]?.totalThreats) || 0;

    // Calculate average scan duration
    const avgDurationResult = await db
      .select({ avgDuration: avg(scanHistory.scanDuration) })
      .from(scanHistory)
      .where(whereCondition);
    
    const averageScanDuration = Math.round((Number(avgDurationResult[0]?.avgDuration) || 0) * 100) / 100;

    // Calculate success rate
    const successCountResult = await db
      .select({ count: count() })
      .from(scanHistory)
      .where(whereCondition ? sql`${whereCondition} AND ${scanHistory.status} = 'success'` : eq(scanHistory.status, 'success'));
    
    const successCount = successCountResult[0]?.count || 0;
    const successRate = Math.round((successCount / totalScans) * 100 * 100) / 100;

    // Fetch recent scans (last 10)
    let recentScansQuery = db
      .select()
      .from(scanHistory)
      .orderBy(desc(scanHistory.scanTimestamp))
      .limit(10);

    if (whereCondition) {
      recentScansQuery = recentScansQuery.where(whereCondition);
    }

    const recentScans = await recentScansQuery;

    return NextResponse.json({
      totalScans,
      averageRiskScore,
      totalThreatsFound,
      averageScanDuration,
      successRate,
      recentScans
    }, { status: 200 });

  } catch (error) {
    console.error('GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + (error instanceof Error ? error.message : String(error)) },
      { status: 500 }
    );
  }
}