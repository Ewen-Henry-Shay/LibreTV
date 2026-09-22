import { NextResponse } from 'next/server';
import {
  SESSION_COOKIE,
  checkRateLimit,
  signSession,
  checkPassword,
  clearRateLimit,
} from '@/lib/auth';

export const runtime = 'edge';  // 改成 edge，删掉 nodejs

export async function POST(req: Request) {
  // 删掉 isPasswordConfigured() 的 503 判断（已硬编码密码，永远配置好了）

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

  // 注意这里加了 await
  if (!await checkPassword(password)) {
    return NextResponse.json({ success: false, error: '密码错误' }, { status: 401 });
  }

  clearRateLimit(ip);
  // 注意这里也加了 await
  const { token, expiresAt } = await signSession();
  const res = NextResponse.json({ success: true });

  // Cookie Secure 直接写死 true（你的域名是 https）
  res.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    maxAge: Math.floor((expiresAt - Date.now()) / 1000),
    path: '/',
  });
  return res;
}

// GET 和 DELETE 如果也用了 sessionFromCookieHeader，同样需要改 async/await
export async function GET(req: Request) {
  // sessionFromCookieHeader 现在返回 Promise<boolean>，需要 await
  const verified = await sessionFromCookieHeader(req.headers.get('cookie'));
  return NextResponse.json({ success: true, verified });
}

export async function DELETE() {
  const res = NextResponse.json({ success: true });
  res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, maxAge: 0, path: '/' });
  return res;
}
