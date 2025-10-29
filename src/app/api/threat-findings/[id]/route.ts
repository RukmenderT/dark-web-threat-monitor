import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { threatFindings } from '@/db/schema';
import { eq } from 'drizzle-orm';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;

    // Validate ID
    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json(
        { error: 'Valid ID is required', code: 'INVALID_ID' },
        { status: 400 }
      );
    }

    const findingId = parseInt(id);

    // Parse request body
    const body = await request.json();
    const {
      category,
      severity,
      title,
      description,
      evidence,
      remediation,
      confidenceScore,
      falsePositive,
    } = body;

    // Validate severity if provided
    if (severity && !VALID_SEVERITIES.includes(severity)) {
      return NextResponse.json(
        {
          error: `Invalid severity. Must be one of: ${VALID_SEVERITIES.join(', ')}`,
          code: 'INVALID_SEVERITY',
        },
        { status: 400 }
      );
    }

    // Validate confidenceScore if provided
    if (confidenceScore !== undefined) {
      const score = parseFloat(confidenceScore);
      if (isNaN(score) || score < 0 || score > 1) {
        return NextResponse.json(
          {
            error: 'Confidence score must be a number between 0.0 and 1.0',
            code: 'INVALID_CONFIDENCE_SCORE',
          },
          { status: 400 }
        );
      }
    }

    // Check if finding exists
    const existingFinding = await db
      .select()
      .from(threatFindings)
      .where(eq(threatFindings.id, findingId))
      .limit(1);

    if (existingFinding.length === 0) {
      return NextResponse.json(
        { error: 'Threat finding not found' },
        { status: 404 }
      );
    }

    // Prepare update data - only include fields that were provided
    const updateData: any = {};

    if (category !== undefined) updateData.category = category;
    if (severity !== undefined) updateData.severity = severity;
    if (title !== undefined) updateData.title = title;
    if (description !== undefined) updateData.description = description;
    if (evidence !== undefined) updateData.evidence = evidence;
    if (remediation !== undefined) updateData.remediation = remediation;
    if (confidenceScore !== undefined) updateData.confidenceScore = parseFloat(confidenceScore);
    if (falsePositive !== undefined) updateData.falsePositive = falsePositive;

    // Update the finding
    const updated = await db
      .update(threatFindings)
      .set(updateData)
      .where(eq(threatFindings.id, findingId))
      .returning();

    if (updated.length === 0) {
      return NextResponse.json(
        { error: 'Threat finding not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(updated[0], { status: 200 });
  } catch (error: any) {
    console.error('PUT error:', error);
    return NextResponse.json(
      { error: 'Internal server error: ' + error.message },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;

    // Validate ID
    if (!id || isNaN(parseInt(id))) {
      return NextResponse.json(
        { error: 'Valid ID is required', code: 'INVALID_ID' },
        { status: 400 }
      );
    }

    const findingId = parseInt(id);

    // Check if finding exists before deleting
    const existingFinding = await db
      .select()
      .from(threatFindings)
      .where(eq(threatFindings.id, findingId))
      .limit(1);

    if (existingFinding.length === 0) {
      return NextResponse.json(
        { error: 'Threat finding not found' },
        { status: 404 }
      );
    }

    // Delete the finding
    const deleted = await db
      .delete(threatFindings)
      .where(eq(threatFindings.id, findingId))
      .returning();

    if (deleted.length === 0) {
      return NextResponse.json(
        { error: 'Threat finding not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(
      {
        message: 'Threat finding deleted successfully',
        id: findingId,
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