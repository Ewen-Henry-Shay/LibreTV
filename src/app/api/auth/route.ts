import { NextResponse } from 'next/server';
import {
  SESSION_COOKIE,
  checkRateLimit,
  signSession,
  checkPassword,
  clearRateLimit,
  sessionFromCookieHeader,
} from '@/lib/auth';

export const runtime = 'edge';

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || 'unknown';
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { success: false, error: '尝试次数过多，请 10 分钟后再试' },
      { status: 429 }
    );
  }

  let password = '';
  try {
    const body = (await req.json()) as { password?: string };
    password = String(body.password ?? '');
  } catch {
    return NextResponse.json({ success: false, error: '请求格式错误' }, { status: 400 });
  }

  if (!await checkPassword(password)) {
    return NextResponse.json({ success: false, error: '密码错误' }, { status: 401 });
  }

  clearRateLimit(ip);
  const { token, expiresAt } = await signSession();
  const res = NextResponse.json({ success: true });
  res.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    maxAge: Math.floor((expiresAt - Date.now()) / 1000),
    path: '/',
  });
  return res;
}

export async function GET(req: Request) {
  const verified = await sessionFromCookieHeader(req.headers.get('cookie'));
  return NextResponse.json({ success: true, verified });
}

export async function DELETE() {
  const res = NextResponse.json({ success: true });
  res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, maxAge: 0, path: '/' });
  return res;
}
