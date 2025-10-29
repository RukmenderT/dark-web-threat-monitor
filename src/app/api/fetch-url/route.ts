import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json();

    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
    }

    // Validate URL format
    let validUrl: URL;
    try {
      validUrl = new URL(url);
    } catch {
      return NextResponse.json(
        { error: 'Invalid URL format' },
        { status: 400 }
      );
    }

    // Fetch content with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout

    try {
      const response = await fetch(validUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate, br',
          'DNT': '1',
          'Connection': 'keep-alive',
          'Upgrade-Insecure-Requests': '1',
        },
        signal: controller.signal,
        redirect: 'follow',
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return NextResponse.json(
          { 
            error: `HTTP ${response.status}: ${response.statusText}`,
            content: '',
            status: response.status
          },
          { status: 200 } // Return 200 but with error info
        );
      }

      const contentType = response.headers.get('content-type') || '';
      
      // Only process text-based content
      if (!contentType.includes('text') && !contentType.includes('html') && !contentType.includes('json')) {
        return NextResponse.json(
          { 
            error: 'Non-text content type',
            content: '',
            contentType
          },
          { status: 200 }
        );
      }

      const text = await response.text();
      
      return NextResponse.json({
        content: text,
        status: response.status,
        contentType,
        length: text.length,
      });

    } catch (fetchError: any) {
      clearTimeout(timeoutId);
      
      if (fetchError.name === 'AbortError') {
        return NextResponse.json(
          { error: 'Request timeout (15s)', content: '' },
          { status: 200 }
        );
      }
      
      return NextResponse.json(
        { error: fetchError.message || 'Failed to fetch URL', content: '' },
        { status: 200 }
      );
    }

  } catch (error: any) {
    console.error('API fetch-url error:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error', content: '' },
      { status: 500 }
    );
  }
}
