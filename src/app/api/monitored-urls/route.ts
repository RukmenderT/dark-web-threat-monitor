import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { monitoredUrls } from '@/db/schema';
import { eq, and } from 'drizzle-orm';

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const type = searchParams.get('type');
    const status = searchParams.get('status');
    const limit = Math.min(parseInt(searchParams.get('limit') ?? '100'), 100);
    const offset = parseInt(searchParams.get('offset') ?? '0');

    let query = db.select().from(monitoredUrls);

    const conditions = [];
    
    if (type) {
      if (type !== 'surface' && type !== 'darkweb') {
        return NextResponse.json({ 
          error: "Type must be 'surface' or 'darkweb'",
          code: "INVALID_TYPE" 
        }, { status: 400 });
      }
      conditions.push(eq(monitoredUrls.type, type));
    }

    if (status) {
      if (status !== 'active' && status !== 'paused' && status !== 'error') {
        return NextResponse.json({ 
          error: "Status must be 'active', 'paused', or 'error'",
          code: "INVALID_STATUS" 
        }, { status: 400 });
      }
      conditions.push(eq(monitoredUrls.status, status));
    }

    if (conditions.length > 0) {
      query = query.where(and(...conditions));
    }

    const results = await query.limit(limit).offset(offset);

    return NextResponse.json(results, { status: 200 });
  } catch (error) {
    console.error('GET error:', error);
    return NextResponse.json({ 
      error: 'Internal server error: ' + (error instanceof Error ? error.message : String(error))
    }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { url, type, status, scanInterval, riskScore, threatCount, lastScan, nextScan } = body;

    if (!url || typeof url !== 'string' || url.trim() === '') {
      return NextResponse.json({ 
        error: "URL is required and cannot be empty",
        code: "INVALID_URL" 
      }, { status: 400 });
    }

    if (!type || (type !== 'surface' && type !== 'darkweb')) {
      return NextResponse.json({ 
        error: "Type is required and must be 'surface' or 'darkweb'",
        code: "INVALID_TYPE" 
      }, { status: 400 });
    }

    if (!status || (status !== 'active' && status !== 'paused' && status !== 'error')) {
      return NextResponse.json({ 
        error: "Status is required and must be 'active', 'paused', or 'error'",
        code: "INVALID_STATUS" 
      }, { status: 400 });
    }

    const newMonitoredUrl = await db.insert(monitoredUrls)
      .values({
        url: url.trim(),
        type,
        status,
        riskScore: riskScore ?? 0,
        threatCount: threatCount ?? 0,
        scanInterval: scanInterval ?? 300,
        lastScan: lastScan ?? null,
        nextScan: nextScan ?? null,
        addedAt: Date.now(),
        updatedAt: null,
      })
      .returning();

    return NextResponse.json(newMonitoredUrl[0], { status: 201 });
  } catch (error) {
    console.error('POST error:', error);
    return NextResponse.json({ 
      error: 'Internal server error: ' + (error instanceof Error ? error.message : String(error))
    }, { status: 500 });
  }
}

export async function PUT(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const id = searchParams.get('id');

    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json({ 
        error: "Valid ID is required",
        code: "INVALID_ID" 
      }, { status: 400 });
    }

    const existing = await db.select()
      .from(monitoredUrls)
      .where(eq(monitoredUrls.id, parseInt(id)))
      .limit(1);

    if (existing.length === 0) {
      return NextResponse.json({ 
        error: 'Monitored URL not found' 
      }, { status: 404 });
    }

    const body = await request.json();
    const { url, type, status, riskScore, threatCount, scanInterval, lastScan, nextScan } = body;

    if (url !== undefined && (typeof url !== 'string' || url.trim() === '')) {
      return NextResponse.json({ 
        error: "URL cannot be empty",
        code: "INVALID_URL" 
      }, { status: 400 });
    }

    if (type !== undefined && type !== 'surface' && type !== 'darkweb') {
      return NextResponse.json({ 
        error: "Type must be 'surface' or 'darkweb'",
        code: "INVALID_TYPE" 
      }, { status: 400 });
    }

    if (status !== undefined && status !== 'active' && status !== 'paused' && status !== 'error') {
      return NextResponse.json({ 
        error: "Status must be 'active', 'paused', or 'error'",
        code: "INVALID_STATUS" 
      }, { status: 400 });
    }

    const updateData: any = {
      updatedAt: Date.now(),
    };

    if (url !== undefined) updateData.url = url.trim();
    if (type !== undefined) updateData.type = type;
    if (status !== undefined) updateData.status = status;
    if (riskScore !== undefined) updateData.riskScore = riskScore;
    if (threatCount !== undefined) updateData.threatCount = threatCount;
    if (scanInterval !== undefined) updateData.scanInterval = scanInterval;
    if (lastScan !== undefined) updateData.lastScan = lastScan;
    if (nextScan !== undefined) updateData.nextScan = nextScan;

    const updated = await db.update(monitoredUrls)
      .set(updateData)
      .where(eq(monitoredUrls.id, parseInt(id)))
      .returning();

    return NextResponse.json(updated[0], { status: 200 });
  } catch (error) {
    console.error('PUT error:', error);
    return NextResponse.json({ 
      error: 'Internal server error: ' + (error instanceof Error ? error.message : String(error))
    }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const id = searchParams.get('id');

    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json({ 
        error: "Valid ID is required",
        code: "INVALID_ID" 
      }, { status: 400 });
    }

    const existing = await db.select()
      .from(monitoredUrls)
      .where(eq(monitoredUrls.id, parseInt(id)))
      .limit(1);

    if (existing.length === 0) {
      return NextResponse.json({ 
        error: 'Monitored URL not found' 
      }, { status: 404 });
    }

    const deleted = await db.delete(monitoredUrls)
      .where(eq(monitoredUrls.id, parseInt(id)))
      .returning();

    return NextResponse.json({ 
      message: "Monitored URL deleted successfully", 
      id: deleted[0].id 
    }, { status: 200 });
  } catch (error) {
    console.error('DELETE error:', error);
    return NextResponse.json({ 
      error: 'Internal server error: ' + (error instanceof Error ? error.message : String(error))
    }, { status: 500 });
  }
}