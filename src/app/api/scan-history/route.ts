import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { scanHistory } from '@/db/schema';
import { eq, and, desc } from 'drizzle-orm';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const urlId = searchParams.get('url_id');
    const status = searchParams.get('status');
    const limit = Math.min(parseInt(searchParams.get('limit') ?? '10'), 100);
    const offset = parseInt(searchParams.get('offset') ?? '0');

    let query = db.select().from(scanHistory);

    // Build filter conditions
    const conditions = [];

    if (urlId) {
      const parsedUrlId = parseInt(urlId);
      if (isNaN(parsedUrlId)) {
        return NextResponse.json({
          error: 'Invalid url_id parameter',
          code: 'INVALID_URL_ID'
        }, { status: 400 });
      }
      conditions.push(eq(scanHistory.urlId, parsedUrlId));
    }

    if (status) {
      const validStatuses = ['success', 'failed', 'error'];
      if (!validStatuses.includes(status)) {
        return NextResponse.json({
          error: 'Invalid status. Must be one of: success, failed, error',
          code: 'INVALID_STATUS'
        }, { status: 400 });
      }
      conditions.push(eq(scanHistory.status, status));
    }

    // Apply filters if any exist
    if (conditions.length > 0) {
      query = query.where(and(...conditions));
    }

    // Order by scanTimestamp DESC and apply pagination
    const results = await query
      .orderBy(desc(scanHistory.scanTimestamp))
      .limit(limit)
      .offset(offset);

    return NextResponse.json(results, { status: 200 });

  } catch (error) {
    console.error('GET error:', error);
    return NextResponse.json({
      error: 'Internal server error: ' + (error as Error).message
    }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { urlId, scanTimestamp, riskScore, threatsFound, scanDuration, status } = body;

    // Validate required fields
    if (!urlId) {
      return NextResponse.json({
        error: 'urlId is required',
        code: 'MISSING_URL_ID'
      }, { status: 400 });
    }

    if (!scanTimestamp) {
      return NextResponse.json({
        error: 'scanTimestamp is required',
        code: 'MISSING_SCAN_TIMESTAMP'
      }, { status: 400 });
    }

    // Validate urlId is a valid integer
    const parsedUrlId = parseInt(urlId);
    if (isNaN(parsedUrlId)) {
      return NextResponse.json({
        error: 'urlId must be a valid integer',
        code: 'INVALID_URL_ID'
      }, { status: 400 });
    }

    // Validate scanTimestamp is a valid integer
    const parsedTimestamp = parseInt(scanTimestamp);
    if (isNaN(parsedTimestamp)) {
      return NextResponse.json({
        error: 'scanTimestamp must be a valid unix timestamp',
        code: 'INVALID_TIMESTAMP'
      }, { status: 400 });
    }

    // Validate status if provided
    if (status) {
      const validStatuses = ['success', 'failed', 'error'];
      if (!validStatuses.includes(status)) {
        return NextResponse.json({
          error: 'status must be one of: success, failed, error',
          code: 'INVALID_STATUS'
        }, { status: 400 });
      }
    }

    // Validate optional integer fields if provided
    if (riskScore !== undefined && riskScore !== null) {
      const parsedRiskScore = parseInt(riskScore);
      if (isNaN(parsedRiskScore)) {
        return NextResponse.json({
          error: 'riskScore must be a valid integer',
          code: 'INVALID_RISK_SCORE'
        }, { status: 400 });
      }
    }

    if (threatsFound !== undefined && threatsFound !== null) {
      const parsedThreatsFound = parseInt(threatsFound);
      if (isNaN(parsedThreatsFound)) {
        return NextResponse.json({
          error: 'threatsFound must be a valid integer',
          code: 'INVALID_THREATS_FOUND'
        }, { status: 400 });
      }
    }

    if (scanDuration !== undefined && scanDuration !== null) {
      const parsedScanDuration = parseInt(scanDuration);
      if (isNaN(parsedScanDuration)) {
        return NextResponse.json({
          error: 'scanDuration must be a valid integer',
          code: 'INVALID_SCAN_DURATION'
        }, { status: 400 });
      }
    }

    // Prepare insert data
    const insertData: any = {
      urlId: parsedUrlId,
      scanTimestamp: parsedTimestamp,
      status: status || 'success'
    };

    // Add optional fields if provided
    if (riskScore !== undefined && riskScore !== null) {
      insertData.riskScore = parseInt(riskScore);
    }

    if (threatsFound !== undefined && threatsFound !== null) {
      insertData.threatsFound = parseInt(threatsFound);
    }

    if (scanDuration !== undefined && scanDuration !== null) {
      insertData.scanDuration = parseInt(scanDuration);
    }

    // Insert the new scan record
    const newRecord = await db.insert(scanHistory)
      .values(insertData)
      .returning();

    return NextResponse.json(newRecord[0], { status: 201 });

  } catch (error) {
    console.error('POST error:', error);
    return NextResponse.json({
      error: 'Internal server error: ' + (error as Error).message
    }, { status: 500 });
  }
}