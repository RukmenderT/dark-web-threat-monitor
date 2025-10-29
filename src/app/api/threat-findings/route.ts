import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { threatFindings } from '@/db/schema';
import { eq, and } from 'drizzle-orm';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const urlId = searchParams.get('url_id');
    const severity = searchParams.get('severity');
    const falsePositive = searchParams.get('false_positive');
    const limit = Math.min(parseInt(searchParams.get('limit') ?? '100'), 100);
    const offset = parseInt(searchParams.get('offset') ?? '0');

    let query = db.select().from(threatFindings);

    const conditions = [];

    if (urlId) {
      const parsedUrlId = parseInt(urlId);
      if (isNaN(parsedUrlId)) {
        return NextResponse.json(
          { error: 'Invalid url_id parameter', code: 'INVALID_URL_ID' },
          { status: 400 }
        );
      }
      conditions.push(eq(threatFindings.urlId, parsedUrlId));
    }

    if (severity) {
      if (!VALID_SEVERITIES.includes(severity as any)) {
        return NextResponse.json(
          { 
            error: `Invalid severity. Must be one of: ${VALID_SEVERITIES.join(', ')}`,
            code: 'INVALID_SEVERITY'
          },
          { status: 400 }
        );
      }
      conditions.push(eq(threatFindings.severity, severity));
    }

    if (falsePositive !== null) {
      const fpValue = falsePositive === 'true';
      conditions.push(eq(threatFindings.falsePositive, fpValue));
    }

    if (conditions.length > 0) {
      query = query.where(and(...conditions));
    }

    const results = await query.limit(limit).offset(offset);

    return NextResponse.json(results, { status: 200 });
  } catch (error: any) {
    console.error('GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + error.message },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { urlId, category, severity, title, description, evidence, remediation, confidenceScore, falsePositive } = body;

    // Validate required fields
    if (!urlId) {
      return NextResponse.json(
        { error: 'urlId is required', code: 'MISSING_URL_ID' },
        { status: 400 }
      );
    }

    if (isNaN(parseInt(urlId))) {
      return NextResponse.json(
        { error: 'urlId must be a valid integer', code: 'INVALID_URL_ID' },
        { status: 400 }
      );
    }

    if (!category || typeof category !== 'string' || category.trim() === '') {
      return NextResponse.json(
        { error: 'category is required and must be a non-empty string', code: 'MISSING_CATEGORY' },
        { status: 400 }
      );
    }

    if (!severity) {
      return NextResponse.json(
        { error: 'severity is required', code: 'MISSING_SEVERITY' },
        { status: 400 }
      );
    }

    if (!VALID_SEVERITIES.includes(severity as any)) {
      return NextResponse.json(
        { 
          error: `severity must be one of: ${VALID_SEVERITIES.join(', ')}`,
          code: 'INVALID_SEVERITY'
        },
        { status: 400 }
      );
    }

    if (!title || typeof title !== 'string' || title.trim() === '') {
      return NextResponse.json(
        { error: 'title is required and must be a non-empty string', code: 'MISSING_TITLE' },
        { status: 400 }
      );
    }

    // Validate confidenceScore if provided
    if (confidenceScore !== undefined && confidenceScore !== null) {
      const score = parseFloat(confidenceScore);
      if (isNaN(score) || score < 0.0 || score > 1.0) {
        return NextResponse.json(
          { error: 'confidenceScore must be a number between 0.0 and 1.0', code: 'INVALID_CONFIDENCE_SCORE' },
          { status: 400 }
        );
      }
    }

    // Prepare insert data
    const insertData: any = {
      urlId: parseInt(urlId),
      category: category.trim(),
      severity,
      title: title.trim(),
      confidenceScore: confidenceScore !== undefined && confidenceScore !== null ? parseFloat(confidenceScore) : 0.0,
      falsePositive: falsePositive !== undefined && falsePositive !== null ? Boolean(falsePositive) : false,
      createdAt: Date.now(),
    };

    if (description !== undefined && description !== null) {
      insertData.description = typeof description === 'string' ? description.trim() : description;
    }

    if (evidence !== undefined && evidence !== null) {
      insertData.evidence = typeof evidence === 'string' ? evidence.trim() : evidence;
    }

    if (remediation !== undefined && remediation !== null) {
      insertData.remediation = typeof remediation === 'string' ? remediation.trim() : remediation;
    }

    const newFinding = await db.insert(threatFindings)
      .values(insertData)
      .returning();

    return NextResponse.json(newFinding[0], { status: 201 });
  } catch (error: any) {
    console.error('POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + error.message },
      { status: 500 }
    );
  }
}

export async function PUT(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const id = searchParams.get('id');

    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json(
        { error: 'Valid id is required', code: 'INVALID_ID' },
        { status: 400 }
      );
    }

    const findingId = parseInt(id);

    // Check if finding exists
    const existing = await db.select()
      .from(threatFindings)
      .where(eq(threatFindings.id, findingId))
      .limit(1);

    if (existing.length === 0) {
      return NextResponse.json(
        { error: 'Threat finding not found' },
        { status: 404 }
      );
    }

    const body = await request.json();
    const { category, severity, title, description, evidence, remediation, confidenceScore, falsePositive } = body;

    // Validate severity if provided
    if (severity && !VALID_SEVERITIES.includes(severity as any)) {
      return NextResponse.json(
        { 
          error: `severity must be one of: ${VALID_SEVERITIES.join(', ')}`,
          code: 'INVALID_SEVERITY'
        },
        { status: 400 }
      );
    }

    // Validate title if provided
    if (title !== undefined && (typeof title !== 'string' || title.trim() === '')) {
      return NextResponse.json(
        { error: 'title must be a non-empty string', code: 'INVALID_TITLE' },
        { status: 400 }
      );
    }

    // Validate category if provided
    if (category !== undefined && (typeof category !== 'string' || category.trim() === '')) {
      return NextResponse.json(
        { error: 'category must be a non-empty string', code: 'INVALID_CATEGORY' },
        { status: 400 }
      );
    }

    // Validate confidenceScore if provided
    if (confidenceScore !== undefined && confidenceScore !== null) {
      const score = parseFloat(confidenceScore);
      if (isNaN(score) || score < 0.0 || score > 1.0) {
        return NextResponse.json(
          { error: 'confidenceScore must be a number between 0.0 and 1.0', code: 'INVALID_CONFIDENCE_SCORE' },
          { status: 400 }
        );
      }
    }

    // Prepare update data
    const updateData: any = {};

    if (category !== undefined) {
      updateData.category = category.trim();
    }

    if (severity !== undefined) {
      updateData.severity = severity;
    }

    if (title !== undefined) {
      updateData.title = title.trim();
    }

    if (description !== undefined) {
      updateData.description = typeof description === 'string' ? description.trim() : description;
    }

    if (evidence !== undefined) {
      updateData.evidence = typeof evidence === 'string' ? evidence.trim() : evidence;
    }

    if (remediation !== undefined) {
      updateData.remediation = typeof remediation === 'string' ? remediation.trim() : remediation;
    }

    if (confidenceScore !== undefined && confidenceScore !== null) {
      updateData.confidenceScore = parseFloat(confidenceScore);
    }

    if (falsePositive !== undefined && falsePositive !== null) {
      updateData.falsePositive = Boolean(falsePositive);
    }

    // Only update if there are fields to update
    if (Object.keys(updateData).length === 0) {
      return NextResponse.json(existing[0], { status: 200 });
    }

    const updated = await db.update(threatFindings)
      .set(updateData)
      .where(eq(threatFindings.id, findingId))
      .returning();

    return NextResponse.json(updated[0], { status: 200 });
  } catch (error: any) {
    console.error('PUT error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + error.message },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const id = searchParams.get('id');

    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json(
        { error: 'Valid id is required', code: 'INVALID_ID' },
        { status: 400 }
      );
    }

    const findingId = parseInt(id);

    // Check if finding exists
    const existing = await db.select()
      .from(threatFindings)
      .where(eq(threatFindings.id, findingId))
      .limit(1);

    if (existing.length === 0) {
      return NextResponse.json(
        { error: 'Threat finding not found' },
        { status: 404 }
      );
    }

    const deleted = await db.delete(threatFindings)
      .where(eq(threatFindings.id, findingId))
      .returning();

    return NextResponse.json(
      { 
        message: 'Threat finding deleted successfully',
        id: deleted[0].id
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('DELETE error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + error.message },
      { status: 500 }
    );
  }
}