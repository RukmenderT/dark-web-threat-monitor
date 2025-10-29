import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { monitoredUrls, threatFindings } from '@/db/schema';
import { eq } from 'drizzle-orm';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const id = params.id;

    // Validate ID
    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json(
        { 
          error: 'Valid ID is required',
          code: 'INVALID_ID' 
        },
        { status: 400 }
      );
    }

    const urlId = parseInt(id);

    // Fetch monitored URL
    const urlRecord = await db
      .select()
      .from(monitoredUrls)
      .where(eq(monitoredUrls.id, urlId))
      .limit(1);

    if (urlRecord.length === 0) {
      return NextResponse.json(
        { error: 'Monitored URL not found' },
        { status: 404 }
      );
    }

    // Fetch related threat findings
    const findings = await db
      .select()
      .from(threatFindings)
      .where(eq(threatFindings.urlId, urlId));

    // Return combined object
    return NextResponse.json(
      {
        url: urlRecord[0],
        findings: findings
      },
      { status: 200 }
    );

  } catch (error: any) {
    console.error('GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + error.message },
      { status: 500 }
    );
  }
}